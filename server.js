'use strict';
/**
 * WIN PRO backend (Render web service)
 * - Serves the single-file frontend from /public
 * - Does the Deriv OAuth 2.0 (Authorization Code + PKCE) token exchange server-side
 * - Keeps the access token in an encrypted, httpOnly cookie (the browser never sees it)
 * - Proxies the few Deriv REST calls the app needs (list accounts, get WebSocket OTP url)
 */
const express = require('express');
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const CLIENT_ID = process.env.DERIV_CLIENT_ID || '34tb6qr80U6IIGqopktV4';
const SCOPE = process.env.OAUTH_SCOPE || 'trade account_manage';
const AUTH_URL = 'https://auth.deriv.com/oauth2/auth';
const TOKEN_URL = 'https://auth.deriv.com/oauth2/token';
const API_BASE = 'https://api.derivws.com/trading/v1/options';

// Must exactly match the redirect URI registered for the app with Deriv.
const BASE_URL = (process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const REDIRECT_URI = process.env.REDIRECT_URI || `${BASE_URL}/callback`;

const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 16) {
  if (IS_PROD) {
    console.error('SESSION_SECRET is missing or too short (min 16 chars). Refusing to start.');
    process.exit(1);
  }
  console.warn('[dev] SESSION_SECRET not set — using a throwaway key; sessions reset on restart.');
}
const KEY = crypto.createHash('sha256').update(SESSION_SECRET || crypto.randomBytes(32)).digest();
const COOKIE = 'wp_session';

// ---------- cookie helpers (AES-256-GCM) ----------
function seal(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString('base64url');
}
function unseal(str) {
  try {
    const raw = Buffer.from(str, 'base64url');
    const d = crypto.createDecipheriv('aes-256-gcm', KEY, raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(12, 28));
    const dec = Buffer.concat([d.update(raw.subarray(28)), d.final()]);
    return JSON.parse(dec.toString('utf8'));
  } catch (e) { return null; }
}
function readCookie(req, name) {
  const h = req.headers.cookie || '';
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
function setSession(res, token, expiresIn) {
  const maxAge = Math.max(60, Math.floor(expiresIn || 3600));
  const value = seal({ t: token, exp: Date.now() + maxAge * 1000 });
  res.append('Set-Cookie',
    `${COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${IS_PROD ? '; Secure' : ''}`);
}
function clearSession(res) {
  res.append('Set-Cookie', `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${IS_PROD ? '; Secure' : ''}`);
}
function getToken(req) {
  const c = readCookie(req, COOKIE);
  if (!c) return null;
  const s = unseal(c);
  if (!s || !s.t || !s.exp || s.exp < Date.now()) return null;
  return s.t;
}

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// CSRF hardening for state-changing calls: JSON only + same-origin only.
app.use('/api', (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const origin = req.headers.origin;
  if (origin) {
    let ok = false;
    try { ok = new URL(origin).host === req.headers.host; } catch (e) {}
    if (!ok) return res.status(403).json({ error: 'Cross-origin request blocked' });
  }
  if (!req.is('application/json')) return res.status(415).json({ error: 'JSON required' });
  next();
});

app.get('/healthz', (req, res) => res.type('text').send('ok'));

// Public, non-secret settings the frontend needs to start the login redirect.
app.get('/api/config', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ clientId: CLIENT_ID, redirectUri: REDIRECT_URI, authUrl: AUTH_URL, scope: SCOPE });
});

// Step 4 of the flow: exchange code + code_verifier for an access token (server-side only).
app.post('/api/session', async (req, res) => {
  const { code, code_verifier } = req.body || {};
  const okStr = (s, min, max) => typeof s === 'string' && s.length >= min && s.length <= max;
  if (!okStr(code, 8, 2048) || !okStr(code_verifier, 43, 128)) {
    return res.status(400).json({ error: 'Invalid login response. Please try again.' });
  }
  try {
    const r = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        code,
        code_verifier,
        redirect_uri: REDIRECT_URI
      })
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.access_token) {
      const msg = (j && (j.error_description || j.error)) || `Token exchange failed (${r.status})`;
      console.warn('token exchange failed:', r.status, j && j.error);
      return res.status(400).json({ error: msg });
    }
    setSession(res, j.access_token, j.expires_in);
    res.json({ ok: true, expires_in: j.expires_in });
  } catch (e) {
    console.error('token exchange error', e);
    res.status(502).json({ error: 'Could not reach Deriv. Try again.' });
  }
});

app.post('/api/logout', (req, res) => { clearSession(res); res.json({ ok: true }); });

// Authenticated proxy to Deriv REST.
async function derivProxy(req, res, method, pathSuffix) {
  const token = getToken(req);
  if (!token) { clearSession(res); return res.status(401).json({ error: 'Not logged in' }); }
  try {
    const r = await fetch(API_BASE + pathSuffix, {
      method,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' }
    });
    const j = await r.json().catch(() => null);
    if (r.status === 401) { clearSession(res); return res.status(401).json({ error: 'Session expired. Log in again.' }); }
    if (!r.ok) {
      const msg = (j && j.errors && j.errors[0] && j.errors[0].message) || (j && j.error && j.error.message) || `Request failed (${r.status})`;
      return res.status(r.status).json({ error: msg });
    }
    res.setHeader('Cache-Control', 'no-store');
    res.json(j);
  } catch (e) {
    console.error('deriv proxy error', e);
    res.status(502).json({ error: 'Could not reach Deriv. Try again.' });
  }
}

app.get('/api/accounts', (req, res) => derivProxy(req, res, 'GET', '/accounts'));
app.post('/api/accounts/:id/otp', (req, res) => {
  if (!/^[A-Za-z0-9_-]{3,40}$/.test(req.params.id)) return res.status(400).json({ error: 'Bad account id' });
  derivProxy(req, res, 'POST', `/accounts/${encodeURIComponent(req.params.id)}/otp`);
});

// Frontend
const pub = path.join(__dirname, 'public');
app.use(express.static(pub, { index: false, maxAge: 0 }));
app.get(['/', '/callback'], (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(pub, 'index.html'));
});
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.listen(PORT, () => {
  console.log(`WIN PRO listening on :${PORT}`);
  console.log(`OAuth client_id=${CLIENT_ID}  redirect_uri=${REDIRECT_URI}`);
});
