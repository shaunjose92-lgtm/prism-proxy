'use strict';
// Staging-only controls for Cipher's Render-hosted HTML-rewriting proxy.
// No credentials are hardcoded. The server fails closed without a test password.
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const zlib = require('node:zlib');
const { Readable, Transform } = require('node:stream');

const MAX_REQUEST_BYTES = 1024 * 1024;     // 1 MiB request bodies
const MAX_RESPONSE_BYTES = 12 * 1024 * 1024; // 12 MiB decoded responses
const MAX_ACTIVE = 8;
const MAX_PER_CLIENT = 4;
const activeClients = new Map();
let activeCount = 0;
const attempts = new Map();

function secureEqual(a, b) {
  return crypto.timingSafeEqual(crypto.createHash('sha256').update(a).digest(), crypto.createHash('sha256').update(b).digest());
}
function gate(req, res) {
  const password = process.env.PRISM_STAGING_PASSWORD || '';
  if (password.length < 20) {
    res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
    res.end('Private staging service is not configured.');
    return false;
  }
  const addr = req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const b = attempts.get(addr) || { time: now, count: 0 };
  if (now - b.time > 15 * 60 * 1000) { b.time = now; b.count = 0; }
  attempts.set(addr, b);
  if (b.count >= 15) {
    res.writeHead(429, { 'content-type': 'text/plain', 'retry-after': '900', 'cache-control': 'no-store' });
    res.end('Too many authentication attempts.');
    return false;
  }
  const auth = req.headers.authorization || '';
  let ok = false;
  if (auth.startsWith('Basic ')) {
    try {
      const raw = Buffer.from(auth.slice(6), 'base64').toString('utf8');
      const delim = raw.indexOf(':');
      ok = delim >= 0 && secureEqual(raw.slice(0, delim), 'cipher-test') && secureEqual(raw.slice(delim + 1), password);
    } catch (_) { /* Treat malformed credentials as invalid. */ }
  }
  if (!ok) {
    b.count++;
    res.writeHead(401, { 'www-authenticate': 'Basic realm="Cipher private staging", charset="UTF-8"', 'content-type': 'text/plain', 'cache-control': 'no-store' });
    res.end('This private test service requires credentials.');
    return false;
  }
  b.count = 0;
  return true;
}
setInterval(() => {
  const expire = Date.now() - 15 * 60 * 1000;
  for (const [ip, b] of attempts) if (b.time < expire) attempts.delete(ip);
}, 15 * 60 * 1000).unref();

function acquireSlot(req, res) {
  const key = req.socket.remoteAddress || 'unknown';
  const count = activeClients.get(key) || 0;
  if (activeCount >= MAX_ACTIVE || count >= MAX_PER_CLIENT) {
    res.writeHead(429, { 'content-type': 'text/plain', 'retry-after': '5' });
    res.end('Cipher staging is busy.');
    return null;
  }
  activeCount++;
  activeClients.set(key, count + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    activeCount--;
    const next = (activeClients.get(key) || 1) - 1;
    if (next <= 0) activeClients.delete(key);
    else activeClients.set(key, next);
  };
}

// Only publicly routable IPv4 is permitted in staging. IPv6 is deliberately
// disallowed until a separate, tested IPv6 egress policy is implemented.
function isPublicIPv4(address) {
  if (net.isIP(address) !== 4) return false;
  const octets = address.split('.').map(Number);
  const [a, b, c] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 168 || (b === 0) || (b === 0 && c === 2) || (b === 88 && c === 99))) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}
function validateTarget(input) {
  let url;
  try { url = new URL(input); }
  catch (_) { throw Object.assign(new Error('Invalid target'), { code: 'BLOCKED_TARGET' }); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !url.hostname ||
      (url.port && url.port !== (url.protocol === 'https:' ? '443' : '80')) ||
      (url.hostname.startsWith('[') || net.isIP(url.hostname) === 6 || (net.isIP(url.hostname) === 4 && !isPublicIPv4(url.hostname))) ||
      /(^|\.)(localhost|local|internal|home|lan|test|invalid|onion)$/.test(url.hostname.toLowerCase()) ||
      url.hostname.toLowerCase() === 'metadata.google.internal') {
    throw Object.assign(new Error('Disallowed target'), { code: 'BLOCKED_TARGET' });
  }
  return url;
}
async function resolvePublicTarget(url) {
  const host = url.hostname;
  if (net.isIP(host) === 4) {
    if (!isPublicIPv4(host)) throw Object.assign(new Error('Private target'), { code: 'BLOCKED_TARGET' });
    return host;
  }
  let addresses;
  try {
    addresses = await Promise.race([
      dns.lookup(host, { family: 4, all: true }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), 5000)),
    ]);
  } catch (_) { throw Object.assign(new Error('Unable to resolve public target'), { code: 'BLOCKED_TARGET' }); }
  if (!addresses.length || addresses.some(({address}) => !isPublicIPv4(address))) {
    throw Object.assign(new Error('Target resolves to a non-public address'), { code: 'BLOCKED_TARGET' });
  }
  return addresses[0].address;
}
function guardedFetch(target, options = {}) {
  return (async () => {
    const url = validateTarget(target);
    const pinned = await resolvePublicTarget(url);
    const protocol = url.protocol === 'https:' ? https : http;
    const method = (options.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'POST'].includes(method)) throw Object.assign(new Error('Method not allowed'), { code: 'BLOCKED_TARGET' });
    const headers = { ...(options.headers || {}), 'accept-encoding': 'identity' };
    return new Promise((resolve, reject) => {
      const r = protocol.request({
        hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search, method, headers, agent: false,
        servername: url.hostname,
        // DNS pinning: connect only to the IP we have already validated.
        lookup: (_host, _opts, cb) => cb(null, pinned, 4),
      }, upstream => {
        const h = new Headers();
        for (const [key, val] of Object.entries(upstream.headers)) {
          if (val === undefined) continue;
          if (Array.isArray(val)) for (const part of val) h.append(key, part);
          else h.set(key, String(val));
        }
        let stream = upstream;
        const encoding = String(upstream.headers['content-encoding'] || '').toLowerCase();
        if (encoding === 'gzip') stream = stream.pipe(zlib.createGunzip());
        else if (encoding === 'deflate') stream = stream.pipe(zlib.createInflate());
        else if (encoding === 'br') stream = stream.pipe(zlib.createBrotliDecompress());
        else if (encoding && encoding !== 'identity') {
          upstream.destroy();
          return reject(new Error('Unsupported content encoding'));
        }
        h.delete('content-encoding');
        h.delete('content-length');
        let transferred = 0;
        const limit = new Transform({ transform(chunk, _enc, done) {
          transferred += chunk.length;
          done(transferred > MAX_RESPONSE_BYTES ? new Error('Response too large') : null, chunk);
        }});
        const limited = stream.pipe(limit);
        // Propagate upstream decompression errors to the response reader.
        stream.on('error', err => limited.destroy(err));
        upstream.on('error', err => limited.destroy(err));
        const status = upstream.statusCode || 502;
        try {
          resolve(new Response(method === 'HEAD' || status === 204 || status === 304 ? null : Readable.toWeb(limited),
            { status, headers: h }));
          if (method === 'HEAD' || status === 204 || status === 304) upstream.resume();
        } catch (e) { upstream.destroy(); reject(e); }
      });
      r.setTimeout(15000, () => r.destroy(new Error('Upstream timed out')));
      r.on('error', reject);
      r.end(options.body);
    });
  })();
}
module.exports = { gate, acquireSlot, validateTarget, isPublicIPv4, resolvePublicTarget, guardedFetch, MAX_REQUEST_BYTES };
