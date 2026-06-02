# Qarfash / Atheer — Secure Backend v4.0

Production-ready, modular backend. Read [`SECURITY_REPORT.md`](./SECURITY_REPORT.md)
for the full audit.

## Quick start

```bash
cp .env.example .env
npm install
npm run genkeys           # generates fresh 50-char secrets to paste into .env
npm run hash <password>   # generates bcrypt hash for ADMIN_PASSWORD_HASH
npm start
```

Open `https://your-host/admin-login.html` to sign in.

## Endpoints

### Public (read-only, rate-limited)
- `GET  /healthz`
- `GET  /api/csrf`                    bootstrap CSRF token
- `GET  /api/data` `/api/sections` `/api/side-menu` `/api/posts`
- `GET  /api/app-status` `/api/app-config`
- `POST /api/posts/:id/view`
- `GET  /api/stream?u=<url>`          Range-aware media proxy (fixes mobile video)
- `GET  /api/detect-type?u=<url>`

### Admin auth
- `POST /api/admin/auth/login`        body: `{username, password}`
- `POST /api/admin/auth/refresh`      uses httpOnly cookie
- `POST /api/admin/auth/logout`
- `GET  /api/admin/auth/me`

### Admin (require JWT + admin role + CSRF)
- `POST /api/admin/cloudinary/sign`   signed Cloudinary upload params
- `GET/POST /api/admin/app-config`    `/app-status`
- `GET/POST/PUT/DELETE /api/admin/sections[/:id]`
- `POST/PUT/DELETE /api/admin/sections/:id/media[/:index]`   ← media-with-title
- `GET/POST/PUT/DELETE /api/admin/posts[/:id]`
- `GET/POST/PUT/DELETE /api/admin/anasheed[/:id]`
- `GET/POST/PUT/DELETE /api/admin/side-menu[/:id]`
- `PUT /api/admin/{sections|posts|anasheed|side-menu}/reorder`
- `GET /api/admin/stats`

Every admin call must include:
- `Authorization: Bearer <accessToken>`
- `X-CSRF-Token: <token from /api/csrf>`
- Credentials (cookie) for the refresh flow
