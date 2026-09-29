# WIN PRO — Deriv OAuth 2.0 (PKCE)

- `index.html` — the app (GitHub Pages) → https://sido6992.github.io/winpro/
- `server.js`, `package.json`, `render.yaml` — token-exchange backend (Render) → https://winpro-oauth.onrender.com

## Flow
1. Browser creates PKCE `code_verifier` / `code_challenge` + `state`, redirects to `https://auth.deriv.com/oauth2/auth`
2. Deriv redirects back to `https://sido6992.github.io/winpro/?code=…&state=…`
3. Browser verifies `state`, sends `code` + `code_verifier` to the Render backend `/api/token`
4. Backend exchanges them at `https://auth.deriv.com/oauth2/token` and returns the access token
5. App calls `GET /trading/v1/options/accounts` (Bearer) → `POST /accounts/{id}/otp` → opens the pre-authenticated WebSocket

## Deriv app settings (required)
Redirect URI registered with Deriv must be exactly `https://sido6992.github.io/winpro/`

## Backend env vars (already set on Render)
`CLIENT_ID`, `ALLOWED_ORIGINS`, `REDIRECT_URIS`
