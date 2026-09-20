# CyberShield Deployment Guide

## Architecture

CyberShield is deployed as three local or hosted components:

- **Frontend:** a Vite production bundle served as static files.
- **Backend:** the FastAPI application served by Uvicorn.
- **Database:** the SQLAlchemy database configured by `DATABASE_URL` (SQLite is supported for local deployments; use a managed production database when the target environment provides one).
- **Storage:** generated reports are written below `REPORT_STORAGE_ROOT`.
- **External services:** scanner targets are contacted by the backend. The default AI provider is the local mock provider; configure an external provider only when required.

This guide documents a reproducible local production-style deployment. No cloud or public deployment is implied.

For the controlled local TLS workflow added on Day 28, see [day28-deployment.md](day28-deployment.md). It uses Caddy for local HTTPS termination, a loopback-only Uvicorn backend, and an HTTP-to-HTTPS redirect. The Caddy `tls internal` certificate is intentionally local and is not a public production certificate.

## Prerequisites

- Windows PowerShell or an equivalent shell
- Python 3.12 64-bit
- Node.js and npm
- A configured backend virtual environment at `backend\.venv`
- A database URL writable by the deployment account

Install backend dependencies from `backend\requirements.txt` and frontend dependencies with `npm install` in `frontend`.

## Environment Variables

Backend settings are read from the environment or `backend\.env`:

| Variable | Required | Description |
|---|---:|---|
| `APP_ENV` | Yes | Use `production` for a production deployment. |
| `HOST` / `PORT` | No | Bind address and port; defaults are `0.0.0.0` and `5000`. |
| `DATABASE_URL` | Yes | SQLAlchemy database URL. |
| `REPORT_STORAGE_ROOT` | Yes | Portable absolute path for generated report files. |
| `JWT_SECRET` | Yes | Random secret of at least 32 characters; the development placeholder is rejected in production. |
| `CORS_ORIGINS` | Yes | Explicit JSON list of allowed frontend origins; wildcard origins are rejected in production. |
| `ENABLE_LEGACY_USER_HEADER` | No | Defaults to `false`; keep disabled in production. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | No | JWT lifetime; defaults to 30 minutes. |
| `AI_PROVIDER` / `AI_API_KEY` / `AI_MODEL` | No | AI provider settings where applicable. |

Frontend settings are read at build time from `frontend\.env`:

```text
VITE_API_BASE_URL=http://127.0.0.1:5000/api/v1
```

Do not put JWT secrets, API keys, or database credentials in frontend variables.

## Local Production Build

From `frontend`:

```powershell
npm exec tsc -- -b
npm run lint
npm run build
```

The output is `frontend\dist`.

## Backend Production Start

After exporting production environment variables and applying migrations:

```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host $env:HOST --port $env:PORT
```

The application initializes required tables on startup for compatibility with the existing local architecture. Use migrations as the authoritative schema process. When running behind the Day 28 Caddy proxy, start Uvicorn with `--proxy-headers --forwarded-allow-ips 127.0.0.1` so the application can safely observe the original HTTPS scheme.

## Frontend Production Serve

For a local production-style check:

```powershell
cd frontend
npm run preview -- --host 127.0.0.1 --port 4173
```

For a hosted deployment, serve `dist` through the platform's static-file server or reverse proxy and configure history-fallback behavior for the SPA routes.

## Database Setup

Use the configured database without resetting or dropping data:

```powershell
cd backend
.\.venv\Scripts\alembic.exe upgrade head
```

`migrations\env.py` reads `DATABASE_URL` from the same settings object as the application. Validate migrations first against an isolated database in a new environment.

## Health Check

`GET /health` returns HTTP 200 and:

```json
{"status":"ok"}
```

This endpoint does not disclose configuration or credentials.

## Readiness Check

`GET /ready` returns HTTP 200 and `{"status":"ready"}` only after a database `SELECT 1` succeeds. Database connection failures return HTTP 503 with the sanitized message `The service is not ready.`.

## CORS

Set `CORS_ORIGINS` to an explicit JSON array containing the deployed frontend origin. Production rejects `*`. The API enables credentials for the configured origins; do not use an origin broader than the actual frontend.

## Security

- Authentication uses bearer JWTs with expiration and production secret validation.
- `X-User-ID` compatibility authentication is disabled by default.
- Ownership checks remain enforced by the backend service and route layers.
- Responses include `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, CSP, and `Permissions-Policy`.
- HSTS is conditional on a production request arriving over HTTPS. The Day 28 local TLS workflow provides a documented way to verify this condition through Caddy; the resulting certificate is still only a local test certificate.
- Keep secrets in the deployment environment or a secret manager, never in source, screenshots, or frontend assets.

## Smoke Test

1. Start the backend with an isolated database, an explicit JWT secret, an explicit CORS origin, and a portable report directory.
2. Run `GET /health` and `GET /ready`; confirm both return 200.
3. Inspect response headers for the security headers listed above.
4. Build and serve `frontend\dist`.
5. Open the frontend and confirm it loads without development-server assumptions.
6. Register or authenticate a test user through the API and call an authenticated endpoint with the returned bearer token.
7. Confirm unauthenticated requests are rejected and that the frontend API base points to `/api/v1`.

## Troubleshooting

- **Configuration validation fails:** check `APP_ENV`, `JWT_SECRET` length, JSON syntax for `CORS_ORIGINS`, and the database URL.
- **Readiness returns 503:** verify the database is reachable and that the deployment account can open the configured database.
- **Frontend API calls fail:** confirm `VITE_API_BASE_URL` was set before `npm run build`, including the `/api/v1` suffix.
- **Migration fails:** run it against the intended database URL and inspect the first migration error; do not drop tables as a troubleshooting shortcut.
- **Report downloads fail:** ensure `REPORT_STORAGE_ROOT` exists or is writable and remains outside untrusted request-controlled paths.

## Deployment Limitations

Day 26 validation is local only. It does not validate cloud infrastructure, public internet exposure, HTTPS termination, HSTS over real TLS, production traffic, external AI services, managed database operations, backups, horizontal scaling, or production-scale performance.
