// WIN PRO — Deriv OAuth 2.0 (PKCE) token-exchange backend.
// Zero dependencies. Runs on Render (Node 18+).
//
// The browser does the PKCE dance; this server only performs the one step Deriv
// requires to happen server-side: exchanging the authorization code (+ code_verifier)
// for an access token at https://auth.deriv.com/oauth2/token.
'use strict';
const http = require('http');

const PORT          = process.env.PORT || 3000;
const CLIENT_ID     = process.env.CLIENT_ID || '34tb6qr80U6IIGqopktV4';
const TOKEN_URL     = process.env.TOKEN_URL || 'https://auth.deriv.com/oauth2/token';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://sido6992.github.io')
  .split(',').map(s => s.trim()).filter(Boolean);
const REDIRECT_URIS = (process.env.REDIRECT_URIS || 'https://sido6992.github.io/winpro/')
  .split(',').map(s => s.trim()).filter(Boolean);

// ---- tiny in-memory rate limit: 20 exchanges / 10 min / IP ----
const hits = new Map();
function limited(ip) {
  const now = Date.now(), win = 10 * 60 * 1000;
  const arr = (hits.get(ip) || []).filter(t => now - t < win);
  arr.push(now); hits.set(ip, arr);
  return arr.length > 20;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 600000)) hits.delete(k); }, 300000).unref();

function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '600');
    return true;
  }
  return !origin; // no Origin header (curl / health checks) is fine; unknown origins are not
}
function send(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}
function readBody(req, max = 10 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > max) { reject(new Error('too_large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const okOrigin = cors(req, res);
  const path = (req.url || '/').split('?')[0];

  if (req.method === 'OPTIONS') { res.writeHead(okOrigin ? 204 : 403); return res.end(); }
  if (req.method === 'GET' && (path === '/' || path === '/health')) {
    return send(res, 200, { ok: true, service: 'winpro-oauth', client_id: CLIENT_ID });
  }
  if (!(req.method === 'POST' && path === '/api/token')) return send(res, 404, { error: 'not_found' });
  if (!okOrigin) return send(res, 403, { error: 'origin_not_allowed' });

  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  if (limited(ip)) return send(res, 429, { error: 'rate_limited' });

  let body;
  try { body = JSON.parse(await readBody(req)); } catch (e) { return send(res, 400, { error: 'invalid_request', error_description: 'Bad JSON body' }); }

  const { code, code_verifier, redirect_uri } = body || {};
  if (typeof code !== 'string' || !code || code.length > 2048) return send(res, 400, { error: 'invalid_request', error_description: 'code missing' });
  if (typeof code_verifier !== 'string' || code_verifier.length < 43 || code_verifier.length > 128) return send(res, 400, { error: 'invalid_request', error_description: 'code_verifier must be 43-128 chars' });
  if (!REDIRECT_URIS.includes(redirect_uri)) return send(res, 400, { error: 'invalid_request', error_description: 'redirect_uri not allowed' });

  try {
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      code, code_verifier, redirect_uri
    });
    const up = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: form
    });
    const text = await up.text();
    let json; try { json = JSON.parse(text); } catch (e) { json = { error: 'bad_upstream_response' }; }
    if (!up.ok) return send(res, up.status, { error: json.error || 'token_exchange_failed', error_description: json.error_description || '' });
    // Forward only what the browser needs.
    return send(res, 200, { access_token: json.access_token, expires_in: json.expires_in, token_type: json.token_type || 'Bearer' });
  } catch (e) {
    return send(res, 502, { error: 'upstream_unreachable', error_description: String(e && e.message || e) });
  }
});

server.listen(PORT, () => console.log('winpro-oauth listening on ' + PORT));
