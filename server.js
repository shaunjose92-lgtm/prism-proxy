// Prism: zero-dependency web proxy. Needs Node 20+.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PREFIX = '/p/';

// ---- Look like a normal, recent desktop Chrome in Australia ----
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const BASE_HEADERS = {
  'user-agent': UA,
  'accept-language': 'en-AU,en;q=0.9',
  'accept-encoding': 'gzip, deflate, br',
  'sec-ch-ua': '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"',
};

// ---------- URL helpers ----------
const toProxy = (url, base) => {
  try {
    const abs = new URL(url, base);
    if (!/^https?:$/.test(abs.protocol)) return url;
    return PREFIX + encodeURIComponent(abs.href);
  } catch { return url; }
};
const fromProxyUrl = (u) => {           // "http://me/p/<enc>" -> real url (or null)
  try {
    const x = new URL(u, 'http://x');
    if (!x.pathname.startsWith(PREFIX)) return null;
    return decodeURIComponent(x.pathname.slice(PREFIX.length));
  } catch { return null; }
};

// ---------- per-user cookie jars (sessions persist => fewer challenges) ----------
const sessions = new Map(); // sid -> { jar: Map, seen: ms }
function getSession(req, res) {
  const m = /(?:^|;\s*)prism_sid=([a-f0-9]{32})/.exec(req.headers.cookie || '');
  let sid = m && m[1];
  if (!sid || !sessions.has(sid)) {
    sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, { jar: new Map(), seen: Date.now() });
    res.setHeader('set-cookie', `prism_sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000`);
  }
  const s = sessions.get(sid);
  s.seen = Date.now();
  return s;
}
setInterval(() => {                       // forget idle sessions after 24h
  const cutoff = Date.now() - 24 * 3600e3;
  for (const [k, v] of sessions) if (v.seen < cutoff) sessions.delete(k);
}, 3600e3).unref();

function storeCookies(session, targetUrl, setCookies) {
  const u = new URL(targetUrl);
  for (const line of setCookies) {
    const parts = line.split(';').map(s => s.trim());
    const eq = parts[0].indexOf('=');
    if (eq < 1) continue;
    const c = { name: parts[0].slice(0, eq), value: parts[0].slice(eq + 1), domain: u.hostname, hostOnly: true, path: '/', secure: false, expires: 0 };
    for (const attr of parts.slice(1)) {
      const [k, ...v] = attr.split('=');
      const val = v.join('=');
      switch (k.toLowerCase()) {
        case 'domain': c.domain = val.replace(/^\./, '').toLowerCase(); c.hostOnly = false; break;
        case 'path': c.path = val || '/'; break;
        case 'secure': c.secure = true; break;
        case 'max-age': c.expires = Date.now() + parseInt(val, 10) * 1000; break;
        case 'expires': if (!c.expires) { const t = Date.parse(val); if (!isNaN(t)) c.expires = t; } break;
      }
    }
    if (!c.hostOnly && !(u.hostname === c.domain || u.hostname.endsWith('.' + c.domain))) continue;
    const key = `${c.domain}|${c.path}|${c.name}`;
    if ((c.expires && c.expires < Date.now()) || c.value === '') session.jar.delete(key);
    else session.jar.set(key, c);
  }
  if (session.jar.size > 400) session.jar.delete(session.jar.keys().next().value);
}
function cookieHeader(session, targetUrl) {
  const u = new URL(targetUrl);
  const out = [];
  for (const [key, c] of session.jar) {
    if (c.expires && c.expires < Date.now()) { session.jar.delete(key); continue; }
    const hostOk = c.hostOnly ? u.hostname === c.domain : (u.hostname === c.domain || u.hostname.endsWith('.' + c.domain));
    if (hostOk && u.pathname.startsWith(c.path) && (!c.secure || u.protocol === 'https:')) out.push(`${c.name}=${c.value}`);
  }
  return out.join('; ');
}

// ---------- tiny cache for static files (fewer requests to sites = fewer flags) ----------
const cache = new Map(); // url -> { status, headers, body, exp }
const CACHE_MAX = 300, CACHE_TTL = 10 * 60e3, CACHE_ITEM_MAX = 2 * 1024 * 1024;
const cacheable = (type) => /^(image\/|font\/|text\/javascript|application\/javascript|application\/x-javascript|application\/font|application\/vnd\.ms-fontobject)/.test(type);
function cacheGet(k) {
  const e = cache.get(k);
  if (!e) return null;
  if (e.exp < Date.now()) { cache.delete(k); return null; }
  cache.delete(k); cache.set(k, e); // refresh LRU order
  return e;
}
function cachePut(k, e) {
  cache.set(k, e);
  while (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
}

// ---------- rewriting ----------
function rewriteCSS(css, base) {
  return css
    .replace(/url\(\s*(['"]?)(?!data:|#)([^'")]+)\1\s*\)/gi, (_, q, u) => `url(${q}${toProxy(u.trim(), base)}${q})`)
    .replace(/@import\s+(['"])([^'"]+)\1/gi, (_, q, u) => `@import ${q}${toProxy(u, base)}${q}`);
}
function rewriteHTML(html, base) {
  html = html
    .replace(/<meta[^>]+http-equiv=["']?(content-security-policy|x-frame-options)["']?[^>]*>/gi, '')
    .replace(/\s(integrity|nonce)=("[^"]*"|'[^']*')/gi, '');
  html = html.replace(/(\s(?:href|src|action|poster|data-src|formaction)=)(["'])(.*?)\2/gi, (m, attr, q, val) => {
    if (/^(#|javascript:|data:|mailto:|tel:|blob:)/i.test(val.trim())) return m;
    return `${attr}${q}${toProxy(val.trim().replace(/&amp;/g, '&'), base)}${q}`;
  });
  html = html.replace(/(\ssrcset=)(["'])(.*?)\2/gi, (m, attr, q, val) => {
    const out = val.split(',').map(part => {
      const [u, ...rest] = part.trim().split(/\s+/);
      return [toProxy(u, base), ...rest].join(' ');
    }).join(', ');
    return `${attr}${q}${out}${q}`;
  });
  html = html.replace(/(<style[^>]*>)([\s\S]*?)(<\/style>)/gi, (m, a, css, b) => a + rewriteCSS(css, base) + b);
  html = html.replace(/(\sstyle=)(["'])(.*?)\2/gi, (m, a, q, css) => a + q + rewriteCSS(css, base) + q);
  html = html.replace(/(<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url=)([^"']+)/gi, (m, a, u) => a + toProxy(u, base));
  const inject = `<script>window.__PROXY_BASE=${JSON.stringify(base)};</script><script src="/client.js"></script>`;
  if (/<head[^>]*>/i.test(html)) return html.replace(/<head[^>]*>/i, m => m + inject);
  return inject + html;
}

// ---------- the proxy ----------
async function handleProxy(req, res) {
  const qIndex = req.url.indexOf('?');
  const rawPath = qIndex === -1 ? req.url : req.url.slice(0, qIndex);
  const extraQuery = qIndex === -1 ? '' : req.url.slice(qIndex);
  let target, tu;
  try {
    tu = new URL(decodeURIComponent(rawPath.slice(PREFIX.length)));
    if (extraQuery) tu.search = extraQuery;
    if (!/^https?:$/.test(tu.protocol)) throw new Error('bad protocol');
    target = tu.href;
  } catch {
    res.writeHead(400, { 'content-type': 'text/plain' });
    return res.end('Bad URL');
  }

  const session = getSession(req, res);
  const isGet = req.method === 'GET';

  // serve static files from cache
  if (isGet && !req.headers.range) {
    const hit = cacheGet(target);
    if (hit) { res.writeHead(hit.status, hit.headers); return res.end(hit.body); }
  }

  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = chunks.length ? Buffer.concat(chunks) : undefined;

  // ---- build browser-like headers ----
  const dest = req.headers['sec-fetch-dest'] || 'document';
  const refererReal = fromProxyUrl(req.headers['referer'] || '');
  const headers = { ...BASE_HEADERS, accept: req.headers['accept'] || '*/*' };
  headers['sec-fetch-dest'] = dest;
  headers['sec-fetch-mode'] = req.headers['sec-fetch-mode'] || (dest === 'document' ? 'navigate' : 'no-cors');
  if (dest === 'document') headers['upgrade-insecure-requests'] = '1';
  if (refererReal) {
    const ro = new URL(refererReal);
    headers['referer'] = refererReal;
    headers['sec-fetch-site'] = ro.origin === tu.origin ? 'same-origin' : (ro.hostname.split('.').slice(-2).join('.') === tu.hostname.split('.').slice(-2).join('.') ? 'same-site' : 'cross-site');
    if (!isGet && req.method !== 'HEAD') headers['origin'] = ro.origin;
  } else {
    headers['sec-fetch-site'] = 'none';
    if (!isGet && req.method !== 'HEAD') headers['origin'] = tu.origin;
  }
  if (dest === 'document' && headers['sec-fetch-site'] === 'none') headers['sec-fetch-user'] = '?1';
  if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
  if (req.headers['range']) headers['range'] = req.headers['range'];
  const ck = cookieHeader(session, target);
  if (ck) headers['cookie'] = ck;

  let upstream;
  try {
    upstream = await fetch(target, { method: req.method, headers, body: ['GET', 'HEAD'].includes(req.method) ? undefined : body, redirect: 'manual' });
  } catch (e) {
    res.writeHead(502, { 'content-type': 'text/html' });
    return res.end(`<body style="font-family:sans-serif;padding:2rem"><h2>Couldn't load that page</h2><p>${String(e.cause?.code || e.message)}</p><a href="/">Back</a></body>`);
  }

  // save cookies the site sent (in the server-side jar, per user)
  const sc = typeof upstream.headers.getSetCookie === 'function' ? upstream.headers.getSetCookie() : [];
  if (sc.length) storeCookies(session, target, sc);

  const out = {};
  upstream.headers.forEach((v, k) => {
    if (['content-security-policy', 'content-security-policy-report-only', 'x-frame-options', 'content-encoding',
         'content-length', 'transfer-encoding', 'strict-transport-security', 'set-cookie', 'connection',
         'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy'].includes(k)) return;
    out[k] = v;
  });
  // keep our own session cookie header if getSession just made one
  const mine = res.getHeader('set-cookie');
  if (mine) out['set-cookie'] = mine;

  if (upstream.status >= 300 && upstream.status < 400 && upstream.headers.get('location')) {
    out.location = toProxy(upstream.headers.get('location'), target);
    res.writeHead(upstream.status, out);
    return res.end();
  }

  const type = (upstream.headers.get('content-type') || '').toLowerCase();
  if (type.includes('text/html')) {
    const html = rewriteHTML(await upstream.text(), target);
    out['content-type'] = 'text/html; charset=utf-8';
    res.writeHead(upstream.status, out);
    return res.end(html);
  }
  if (type.includes('text/css')) {
    const css = rewriteCSS(await upstream.text(), target);
    res.writeHead(upstream.status, out);
    return res.end(css);
  }

  // static files: buffer small ones and cache them
  const len = parseInt(upstream.headers.get('content-length') || '0', 10);
  if (isGet && upstream.status === 200 && !req.headers.range && cacheable(type) && (!len || len < CACHE_ITEM_MAX)) {
    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length < CACHE_ITEM_MAX) {
      const h = { ...out, 'content-length': buf.length };
      delete h['set-cookie'];
      cachePut(target, { status: 200, headers: h, body: buf, exp: Date.now() + CACHE_TTL });
      res.writeHead(200, { ...h, ...(mine ? { 'set-cookie': mine } : {}) });
      return res.end(buf);
    }
    res.writeHead(200, out);
    return res.end(buf);
  }

  // everything else streams straight through
  res.writeHead(upstream.status, out);
  if (!upstream.body) return res.end();
  const reader = upstream.body.getReader();
  req.on('close', () => reader.cancel().catch(() => {}));
  try { for (;;) { const { done, value } = await reader.read(); if (done) break; res.write(value); } } catch {}
  res.end();
}

// ---------- static files ----------
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function serveStatic(req, res) {
  let p = req.url.split('?')[0];
  if (p === '/') p = '/index.html';
  const file = path.join(__dirname, 'public', path.normalize(p).replace(/^(\.\.[\/\\])+/, ''));
  if (!file.startsWith(path.join(__dirname, 'public'))) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
}

http.createServer((req, res) => {
  if (req.url.startsWith(PREFIX)) return handleProxy(req, res).catch(e => { try { res.writeHead(500); res.end('Error: ' + e.message); } catch {} });
  serveStatic(req, res);
}).listen(PORT, () => console.log('Prism running on http://localhost:' + PORT));
