# Archive — Secure Media Archive

Archive is a production-oriented Arabic media archive built on Express, Firebase Realtime Database, signed Cloudinary uploads, and a responsive browser interface. It supports posts, sections, side menus, audio, images, PDF documents, direct video URLs, and embeddable video platforms.

## Quick start

```bash
cp .env.example .env
npm install
npm run genkeys
npm run hash "a-long-password-at-least-16-chars"
# Put the generated values and your Firebase/Cloudinary settings in .env
npm start
```

Open `/` for the public archive and `/admin-login.html` for the protected administration panel.

## Media behavior

Uploaded files are sent to Cloudinary through a short-lived signed request. The interface accepts images, audio, video, and PDF files up to 200 MB per file. Direct media URLs are normalized through `/api/stream`, which preserves byte ranges and derives a useful content type when a provider returns `application/octet-stream`. PDF files open through a same-origin inline viewer instead of relying on Google Viewer. YouTube, Vimeo, Facebook, TikTok, Dailymotion, SoundCloud, Twitch, and Archive.org pages use their appropriate embed players when supported.

## API overview

| Area | Routes |
|---|---|
| Public | `GET /healthz`, `/api/data`, `/api/sections`, `/api/side-menu`, `/api/posts`, `/api/app-config`, `/api/app-status` |
| Media | `GET /api/stream?u=<url>&type=<type>&mime=<mime>`, `HEAD /api/stream`, `GET /api/detect-type?u=<url>`, `GET /api/resolve?u=<url>` |
| Admin auth | `POST /api/admin/auth/login`, `/refresh`, `/logout`, `GET /api/admin/auth/me` |
| Admin data | CRUD for `/api/admin/posts`, `/sections`, `/anasheed`, `/side-menu`, plus app config/status and reorder endpoints |
| Admin uploads | `POST /api/admin/cloudinary/sign` |

All admin data routes require a valid access JWT, the `admin` role, and a CSRF token. The refresh token is stored in a signed, httpOnly cookie.

## Required environment values

Production requires `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `CSRF_SECRET`, `COOKIE_SECRET`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD_HASH`. Configure Firebase with `FIREBASE_DB_URL` and its authentication token/secret, and configure signed Cloudinary uploads with `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, and `CLOUDINARY_API_SECRET`. Set `ALLOWED_ORIGINS` explicitly for cross-origin deployments and `FORCE_HTTPS=true` behind HTTPS.

## Verification

The repository includes `AUDIT_ARCHIVE.md`, which records the full pre-change audit and the remediation plan. Run `node --check` against the JavaScript files and start the server with test environment values to verify `/healthz`, `/admin.html` protection, `/api/detect-type`, and `/api/stream`.
