'use strict';
// Cipher Prism proxy — private, security-hardened testing build.
// Compatible with the original /p/, /search and public/ endpoints.
// For public launch replace the shared staging password with real per-user Cipher authentication.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { gate, acquireSlot, guardedFetch, MAX_REQUEST_BYTES } = require('./security-gateway');

const PORT = Number(process.env.PORT) || 3000;
const PREFIX = '/p/';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const BASE_HEADERS = {
  'user-agent': UA,
  'accept-language': 'en-AU,en;q=0.9',
  'accept': '*/*',
  'accept-encoding': 'identity',
};

function toProxy(input, base) {
  try {
    const u = new URL(input, base);
    if (!/^https?:$/.test(u.protocol)) return input;
    return PREFIX + encodeURIComponent(u.href);
  } catch { return input; }
}
function fromProxyUrl(input) {
  try {
    const url = new URL(input, 'http://invalid.local');
    if (!url.pathname.startsWith(PREFIX)) return null;
    const t = new URL(decodeURIComponent(url.pathname.slice(PREFIX.length)));
    return /^https?:$/.test(t.protocol) ? t.href : null;
  } catch { return null; }
}
function error(res, code, msg, headers = {}) {
  if (res.headersSent) { res.destroy(); return; }
  res.writeHead(code, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers });
  res.end(msg);
}

// Each browser visitor has an independent in-memory cookie jar; no caching is shared.
const sessions = new Map();
const MAX_SESSIONS = 100;
function sessionFor(req, res) {
  const found = /(?:^|;\s*)prism_sid=([a-f0-9]{32})(?:;|$)/.exec(req.headers.cookie || '');
  let sid = found?.[1];
  if (!sid || !sessions.has(sid)) {
    sid = crypto.randomBytes(16).toString('hex');
    if (sessions.size >= MAX_SESSIONS) sessions.delete(sessions.keys().next().value);
    sessions.set(sid, { jar: new Map(), seen: Date.now() });
    // Partitioned cookies are intended for Chromium's cross-site iframe handling.
    // A browser may reject third-party cookies; the fallback is to open separately.
    res.setHeader('set-cookie', `prism_sid=${sid}; Path=/; HttpOnly; Secure; SameSite=None; Partitioned; Max-Age=86400`);
  }
  const s = sessions.get(sid);
  s.seen = Date.now();
  return s;
}
setInterval(() => {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const [k, v] of sessions) if (v.seen < cutoff) sessions.delete(k);
}, 3600000).unref();
function storeCookies(session, targetUrl, setCookies) {
  const u = new URL(targetUrl);
  for (const line of setCookies) {
    if (typeof line !== 'string') continue;
    const parts = line.split(';').map(x => x.trim());
    const eq = parts[0].indexOf('=');
    if (eq < 1) continue;
    const c = { name: parts[0].slice(0, eq), value: parts[0].slice(eq + 1), domain: u.hostname, hostOnly: true, path: '/', secure: false, expires: 0 };
    for (const attr of parts.slice(1)) {
      const [raw, ...rest] = attr.split('=');
      const k = raw.toLowerCase(), val = rest.join('=');
      if (k === 'domain') { // Ignore Domain attributes in private staging: prevent public-suffix/sibling-domain cookie injection.
        // Preserving only host-bound cookies means some cross-subdomain logins may not work.
        continue;
      }
      else if (k === 'path') c.path = val || '/';
      else if (k === 'secure') c.secure = true;
      else if (k === 'max-age') { const n = Number(val); if (Number.isFinite(n)) c.expires = Date.now() + n * 1000; }
      else if (k === 'expires' && !c.expires) { const t = Date.parse(val); if (!Number.isNaN(t)) c.expires = t; }
    }
    if (!c.hostOnly && !(u.hostname === c.domain || u.hostname.endsWith('.' + c.domain))) continue;
    const key = `${c.domain}|${c.path}|${c.name}`;
    if ((c.expires && c.expires <= Date.now()) || c.value === '') session.jar.delete(key);
    else session.jar.set(key, c);
    if (session.jar.size > 150) session.jar.delete(session.jar.keys().next().value);
  }
}
function cookieHeader(session, targetUrl) {
  const u = new URL(targetUrl);
  const matches = [];
  for (const [key, c] of session.jar) {
    if (c.expires && c.expires < Date.now()) { session.jar.delete(key); continue; }
    if ((c.hostOnly ? u.hostname === c.domain : u.hostname === c.domain || u.hostname.endsWith('.' + c.domain)) &&
        u.pathname.startsWith(c.path) && (!c.secure || u.protocol === 'https:')) matches.push(`${c.name}=${c.value}`);
  }
  return matches.join('; ');
}

// HTML rewriting remains compatible with the original Cipher Prism client.js.
function rewriteCSS(css, base) {
  return css.replace(/url\(\s*(['"]?)(?!data:|#)([^'")]+)\1\s*\)/gi, (_, q, u) => `url(${q}${toProxy(u.trim(), base)}${q})`)
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (_, q, u) => `@import ${q}${toProxy(u, base)}${q}`);
}
function rewriteHTML(html, base) {
  html = html.replace(/<meta[^>]+http-equiv=["']?(content-security-policy|x-frame-options)["']?[^>]*>/gi, '')
    .replace(/\s(integrity|nonce)=(["'][^"']*["'])/gi, '');
  html = html.replace(/(\s(?:href|src|action|poster|data-src|formaction)=)(["'])(.*?)\2/gi, (m, attr, q, val) => {
    if (/^(#|javascript:|data:|mailto:|tel:|blob:)/i.test(val.trim())) return m;
    return `${attr}${q}${toProxy(val.trim().replace(/&amp;/g, '&'), base)}${q}`;
  });
  html = html.replace(/(\ssrcset=)(["'])(.*?)\2/gi, (_m, attr, q, val) => {
    const out = val.split(',').map(part => {
      const [u, ...rest] = part.trim().split(/\s+/);
      return [toProxy(u, base), ...rest].join(' ');
    }).join(', ');
    return `${attr}${q}${out}${q}`;
  });
  html = html.replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi, (_m, a, css, b) => a + rewriteCSS(css, base) + b);
  html = html.replace(/(\sstyle=)(["'])(.*?)\2/gi, (_m, a, q, css) => a + q + rewriteCSS(css, base) + q);
  html = html.replace(/(<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url=)([^"']+)/gi, (_m, a, u) => a + toProxy(u, base));
  const inject = `<script>window.__PROXY_BASE=${JSON.stringify(base).replace(/</g, '\\u003c')};</script><script src="/client.js"></script>`;
  return /<head[^>]*>/i.test(html) ? html.replace(/<head[^>]*>/i, m => m + inject) : inject + html;
}

async function readBody(req) {
  const n = Number(req.headers['content-length']);
  if (Number.isFinite(n) && n > MAX_REQUEST_BYTES) throw Object.assign(new Error('Large request'), { status: 413 });
  let size = 0;
  const parts = [];
  for await (const b of req) {
    size += b.length;
    if (size > MAX_REQUEST_BYTES) throw Object.assign(new Error('Large request'), { status: 413 });
    parts.push(b);
  }
  return parts.length ? Buffer.concat(parts) : undefined;
}
async function handleProxy(req, res) {
  if (!['GET', 'HEAD', 'POST'].includes(req.method)) return error(res, 405, 'Method not permitted');
  const idx = req.url.indexOf('?');
  const raw = idx === -1 ? req.url : req.url.slice(0, idx);
  const extra = idx === -1 ? '' : req.url.slice(idx);
  let tu;
  try {
    tu = new URL(decodeURIComponent(raw.slice(PREFIX.length)));
    if (extra) tu.search = extra;
    if (!/^https?:$/.test(tu.protocol)) throw new Error('Protocol');
  } catch { return error(res, 400, 'Invalid website URL'); }
  const target = tu.href;
  const session = sessionFor(req, res);
  let body;
  try { body = await readBody(req); }
  catch (e) { return error(res, e.status || 400, 'Request body too large'); }
  const dest = req.headers['sec-fetch-dest'] || 'document';
  const referer = fromProxyUrl(req.headers.referer || '');
  const headers = { ...BASE_HEADERS, accept: req.headers.accept || '*/*' };
  headers['sec-fetch-dest'] = dest;
  headers['sec-fetch-mode'] = req.headers['sec-fetch-mode'] || (dest === 'document' ? 'navigate' : 'no-cors');
  if (dest === 'document') headers['upgrade-insecure-requests'] = '1';
  if (referer) {
    const from = new URL(referer);
    headers.referer = referer;
    headers['sec-fetch-site'] = from.origin === tu.origin ? 'same-origin' : 'cross-site';
    if (req.method === 'POST') headers.origin = from.origin;
  } else {
    headers['sec-fetch-site'] = 'none';
    if (req.method === 'POST') headers.origin = tu.origin;
  }
  if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
  if (req.headers.range) headers.range = req.headers.range;
  const cookies = cookieHeader(session, target);
  if (cookies) headers.cookie = cookies;

  let upstream;
  try { upstream = await guardedFetch(target, { method: req.method, headers, body }); }
  catch (e) { return error(res, e.code === 'BLOCKED_TARGET' ? 403 : 502, e.code === 'BLOCKED_TARGET' ? 'This website is not permitted.' : 'This website could not be loaded.'); }

  const setCookies = typeof upstream.headers.getSetCookie === 'function' ? upstream.headers.getSetCookie() : [];
  if (setCookies.length) storeCookies(session, target, setCookies);
  const out = { 'cache-control': 'private, no-store', 'x-content-type-options': 'nosniff' };
  const rejected = new Set(['content-security-policy','content-security-policy-report-only','x-frame-options','content-encoding','content-length','transfer-encoding','strict-transport-security','set-cookie','connection','cross-origin-opener-policy','cross-origin-embedder-policy','cross-origin-resource-policy','content-disposition','refresh']);
  upstream.headers.forEach((v, k) => { if (!rejected.has(k.toLowerCase())) out[k] = v; });
  // Preserve the server's own per-browser session cookie.
  const issued = res.getHeader('set-cookie');
  if (issued) out['set-cookie'] = issued;
  if (upstream.status >= 300 && upstream.status < 400 && upstream.headers.has('location')) {
    out.location = toProxy(upstream.headers.get('location'), target);
    res.writeHead(upstream.status, out);
    return res.end();
  }
  const mime = (upstream.headers.get('content-type') || '').toLowerCase();
  if (mime.includes('text/html')) {
    const html = rewriteHTML(await upstream.text(), target);
    res.writeHead(upstream.status, { ...out, 'content-type': 'text/html; charset=utf-8' });
    return req.method === 'HEAD' ? res.end() : res.end(html);
  }
  if (mime.includes('text/css')) {
    const css = rewriteCSS(await upstream.text(), target);
    res.writeHead(upstream.status, out);
    return req.method === 'HEAD' ? res.end() : res.end(css);
  }
  res.writeHead(upstream.status, out);
  if (!upstream.body || req.method === 'HEAD') return res.end();
  const reader = upstream.body.getReader();
  req.on('close', () => reader.cancel().catch(() => {}));
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done || res.destroyed) break;
      if (!res.write(value)) await new Promise(resolve => res.once('drain', resolve));
    }
  } catch { res.destroy(); return; }
  res.end();
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.png': 'image/png' };
const STATIC_ROOT = path.resolve(__dirname, 'public');
function serveStatic(req, res) {
  if (!['GET','HEAD'].includes(req.method)) return error(res, 405, 'Method not permitted');
  let urlPath;
  try { urlPath = decodeURIComponent(new URL(req.url, 'http://invalid.local').pathname); }
  catch { return error(res, 400, 'Bad path'); }
  if (urlPath === '/') urlPath = '/index.html';
  const file = path.resolve(STATIC_ROOT, '.' + urlPath);
  if (file !== STATIC_ROOT && !file.startsWith(STATIC_ROOT + path.sep)) return error(res, 403, 'Not permitted');
  fs.readFile(file, (err, data) => {
    if (err) return error(res, 404, 'Not found');
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    res.end(req.method === 'HEAD' ? undefined : data);
  });
}

// Search engine shortcuts: same /search endpoint as the original Prism app.
const ENGINES = [
  q => `https://html.duckduckgo.com/html/?q=${q}`,
  q => `https://lite.duckduckgo.com/lite/?q=${q}`,
  q => `https://www.bing.com/search?q=${q}`,
  q => `https://search.brave.com/search?q=${q}`,
];
const engineDown = new Map();
let lastGood = -1, lastGoodUntil = 0;
async function handleSearch(req, res) {
  if (req.method !== 'GET') return error(res, 405, 'Method not permitted');
  const query = (new URL(req.url, 'http://invalid.local').searchParams.get('q') || '').trim().slice(0, 256);
  if (!query) { res.writeHead(302, { location: '/' }); return res.end(); }
  const eq = encodeURIComponent(query);
  let chosen = lastGoodUntil > Date.now() ? lastGood : -1;
  for (let i = 0; chosen < 0 && i < ENGINES.length; i++) {
    if ((engineDown.get(i) || 0) > Date.now()) continue;
    try {
      const resp = await guardedFetch(ENGINES[i](eq), { method: 'GET', headers: { ...BASE_HEADERS, accept: 'text/html' } });
      const t = await resp.text();
      if (resp.status === 200 && !/anomaly|captcha|unusual traffic/i.test(t)) {
        chosen = i; lastGood = i; lastGoodUntil = Date.now() + 300000;
        break;
      }
    } catch { /* Try next engine. */ }
    engineDown.set(i, Date.now() + 300000);
  }
  if (chosen < 0) chosen = ENGINES.length - 1;
  res.writeHead(302, { location: PREFIX + encodeURIComponent(ENGINES[chosen](eq)), 'cache-control': 'no-store' });
  res.end();
}

// Access gate applies to ALL routes, including /p/, /search and static resources.
const server = http.createServer((req, res) => {
  if (!gate(req, res)) return;
  if (req.url.startsWith(PREFIX) || req.url.startsWith('/search')) {
    const release = acquireSlot(req, res);
    if (!release) return;
    const task = req.url.startsWith(PREFIX) ? handleProxy(req, res) : handleSearch(req, res);
    return Promise.resolve(task).catch(() => error(res, 502, 'Request failed.')).finally(release);
  }
  return serveStatic(req, res);
});
server.requestTimeout = 20000;
server.headersTimeout = 15000;
server.listen(PORT, '0.0.0.0', () => console.log(`Cipher Prism private testing service listening on port ${PORT}`));
