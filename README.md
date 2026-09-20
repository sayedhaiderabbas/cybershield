# CyberShield

CyberShield is a security-operations platform for small businesses and teams
without dedicated security staff. It turns authorized website checks into
prioritized findings, remediation guidance, risk posture, monitoring, alerts,
audit activity, reports, and constrained AI assistance.

This repository is a source release for local development and security review.
It does not claim public hosting, public HTTPS, or production deployment.

## Features

- Owner-scoped businesses and websites
- Authorized, safety-limited website scanning
- Findings with severity, evidence, risk, and remediation guidance
- Remediation tracking and security posture summaries
- Scheduled monitoring and change alerts
- Security activity and audit history
- Assessment report generation
- Constrained AI assistant with input handling and redaction safeguards
- JWT authentication, validation, sanitized errors, and security headers

## Architecture

CyberShield uses a modular-monolith architecture:

- `frontend/` contains the React/Vite client.
- `backend/` contains the FastAPI API, SQLAlchemy models, services, and Alembic
  migrations.
- `scanner/` contains safety-conscious website checks.
- `docs/` contains design, security, testing, and operations documentation.
- `tests/` and `backend/tests/` contain automated verification.

## Technology stack

React, TypeScript, Vite, FastAPI, Python, SQLAlchemy, Alembic, SQLite, JWT,
and a local mock AI provider for deterministic development.

## Security model

Authentication uses JWTs supplied through the API login flow. Authorization is
owner-scoped, request payloads are validated, protected endpoints require
authentication, and responses include security headers. Audit events record
important user and system actions. Scanner controls restrict requests,
redirects, response sizes, concurrency, and private-network access.

## Local setup

Requirements:

- Python 3.12+
- Node.js and npm
- A Python virtual environment with backend dependencies

Create local environment files from the safe templates:

```powershell
Copy-Item .env.example .env
Copy-Item backend\.env.example backend\.env
Copy-Item frontend\.env.example frontend\.env
```

Supply local values through environment variables. Never commit `.env` files,
credentials, tokens, or local databases.

Start the backend:

```powershell
Set-Location backend
& '.venv\Scripts\python.exe' -m uvicorn app.main:app --host 127.0.0.1 --port 5000
```

Start the frontend in another terminal:

```powershell
Set-Location frontend
$env:VITE_API_BASE_URL = 'http://127.0.0.1:5000/api/v1'
npm run dev -- --host 127.0.0.1 --port 4173
```

For a local demo, provide a temporary `DEMO_PASSWORD` and use an isolated
development database. Do not use production credentials or a production
database for demonstrations.

## Environment variables

See `.env.example`, `backend/.env.example`, and `frontend/.env.example`.
Secrets such as `JWT_SECRET` and provider API keys must be supplied through the
runtime environment, for example:

```text
JWT_SECRET=change-me-in-production
AI_API_KEY=
```

The values above are placeholders only and must be replaced locally.

## Testing

Backend:

```powershell
Set-Location backend
& '.venv\Scripts\python.exe' -m pytest -q
```

Frontend:

```powershell
Set-Location frontend
npm exec tsc -- -b
npm run lint
npm run build
```

## Production limitations

The public release has not been operated as a public production service.
Public deployment, public CA TLS, cloud availability, production traffic, SLA,
and production-scale performance are not demonstrated. Caddy/TLS configuration
is readiness material only. Review and apply migrations deliberately in a
controlled environment; do not migrate an active database without a backup and
an approved change plan.

## Responsible use and security disclaimer

Only use CyberShield against websites and systems you own or are explicitly
authorized to assess. The scanner is intended for safe, bounded checks and is
not a substitute for professional penetration testing, incident response, or
compliance advice. Report security issues privately to the maintainers and
never publish credentials, private data, tokens, or exploit material.

## License

See [LICENSE](LICENSE).
