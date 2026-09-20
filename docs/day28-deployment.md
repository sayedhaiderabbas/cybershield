# Day 28 Deployment and TLS Readiness

## Scope

Day 28 adds a controlled local production-style deployment path. It does not claim public deployment, a publicly trusted certificate, or cloud infrastructure.

The deployment topology is:

```text
Browser
  ├─ http://localhost:8080  -> Caddy redirect -> https://localhost:8443
  └─ https://localhost:8443 -> Caddy TLS/static frontend
                                  └─ /api/*, /health, /ready, /docs -> Uvicorn 127.0.0.1:5058
```

Caddy terminates TLS and serves the built frontend. Uvicorn remains bound to loopback and is started with proxy-header support restricted to the local proxy. The backend therefore sees the original HTTPS scheme and can emit production HSTS for HTTPS requests.

## Prerequisites

- Windows PowerShell
- Python 3.12 64-bit and `backend\.venv`
- Node.js and npm
- Caddy installed separately and available as `caddy.exe` on `PATH`

No Caddy binary or certificate/private key is committed to the repository.

## Start the local TLS workflow

Use a temporary synthetic password and a randomly generated JWT secret in the shell:

```powershell
$env:DAY28_PASSWORD = 'set-a-temporary-password-here'
$env:DAY28_JWT_SECRET = 'generate-a-random-secret-of-at-least-32-characters'
.\scripts\start-day28.ps1
```

The script creates only `.day28`, seeds the existing synthetic demo records, builds the frontend with the same-origin `/api/v1` base URL, starts Uvicorn on `127.0.0.1:5058`, and launches the repository Caddy configuration.

The local endpoints are:

- `http://localhost:8080` — redirect listener
- `https://localhost:8443` — TLS frontend and API entry point
- `https://localhost:8443/health` — liveness
- `https://localhost:8443/ready` — database readiness
- `https://localhost:8443/docs` — API documentation

The Caddy `tls internal` directive creates a local certificate authority and certificate. Browser trust warnings are expected unless the operator explicitly trusts Caddy's local root. This is local test TLS, not a production certificate.

## Verification

Verify the redirect without following it:

```powershell
curl.exe -k -I http://localhost:8080/
```

Verify TLS and the certificate:

```powershell
curl.exe -k -I https://localhost:8443/
curl.exe -k -I https://localhost:8443/health
```

The `-k` option is intentional for the untrusted local certificate. It must not be copied into production health checks. Confirm that the response is HTTPS, the certificate negotiation succeeds, and the response includes `Strict-Transport-Security`, `Content-Security-Policy`, `Permissions-Policy`, `Referrer-Policy`, `X-Content-Type-Options`, and `X-Frame-Options`.

Verify protected API behavior through the same HTTPS origin:

```powershell
curl.exe -k -i https://localhost:8443/api/v1/businesses
```

This must return the repository's sanitized HTTP 401 response without a bearer token. Authenticate through the real frontend using the temporary demo credentials; do not place credentials or tokens in screenshots or documentation.

## Security configuration

- `APP_ENV=production` rejects the placeholder JWT secret and wildcard CORS.
- CORS is restricted to `https://localhost:8443`.
- The frontend uses a relative API base URL, so browser API requests are same-origin through Caddy.
- Uvicorn accepts forwarded headers only from `127.0.0.1`.
- The application retains its existing security headers and conditional HSTS behavior.
- Authentication, ownership checks, sanitized errors, readiness, reports, audit logging, scanner behavior, risk calculations, and AI controls are unchanged.

## Cleanup

Stop Caddy and the child Uvicorn process with `Ctrl+C`, then remove only the temporary runtime:

```powershell
.\scripts\reset-day28.ps1
```

The cleanup script deletes only `.day28`. It does not touch databases, reports, evidence, or source files outside that directory.

## Limitations

This workflow validates local TLS termination and proxy behavior only. It does not validate a public certificate authority, public DNS, cloud deployment, managed databases, backups, CDN/WAF behavior, load scaling, or production certificate renewal.
