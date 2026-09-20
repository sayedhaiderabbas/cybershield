# CyberShield Demo Guide

## Prerequisites

- Windows PowerShell
- Python 3.12 64-bit
- Node.js and npm
- Backend dependencies installed in `backend\.venv`
- Frontend dependencies installed in `frontend\node_modules`

## Setup

Use a temporary local password; do not commit it or place it in this guide:

```powershell
$env:DEMO_PASSWORD = 'set-a-temporary-password-here'
$env:DEMO_EMAIL = 'demo@example.invalid'
```

The demo startup script uses the isolated `.demo` directory for its SQLite database and report artifacts. It does not modify `backend\cybershield.db`, `backend\cybershield-final.db`, or evidence files.

## Database

The startup script initializes the existing SQLAlchemy schema and idempotently seeds synthetic demonstration records:

- demo user and business
- website
- two completed scans
- high, medium, and low findings
- enabled monitoring target with comparison scans
- generated report
- open alert
- audit event

Run `scripts\reset-demo.ps1` only when the backend is stopped and a clean isolated demo database is desired. It deletes only `.demo`.

## Backend

From the project root:

```powershell
$env:DEMO_PASSWORD = 'set-a-temporary-password-here'
.\scripts\start-demo.ps1
```

The backend listens on `0.0.0.0:5000` by default, making it reachable from the local machine and browser automation. Use `HOST=127.0.0.1` if loopback-only access is preferred. If the browser uses a non-loopback host address, add the frontend origin to `CORS_ORIGINS` before startup.

## Frontend

In a second terminal:

```powershell
cd frontend
$env:VITE_API_BASE_URL = 'http://127.0.0.1:5000/api/v1'
npm run build
npm run preview -- --host 0.0.0.0 --port 4173
```

Open `http://127.0.0.1:4173`.

## Health verification

```powershell
curl.exe http://127.0.0.1:5000/health
curl.exe http://127.0.0.1:5000/ready
```

Expected responses are `{"status":"ok"}` and `{"status":"ready"}`.

## Login

Use the `DEMO_EMAIL` and temporary `DEMO_PASSWORD` values supplied in the shell. The password is never stored in source code or this guide.

## Demo flow

1. Log in through the real frontend.
2. Show the dashboard security posture, findings count, alerts, and recent activity.
3. Open **Findings** and show the seeded severity distribution and finding details.
4. Open **Security Posture** to explain the deterministic risk summary.
5. Open **Monitoring** and show the enabled target, latest scan, findings, and risk comparison.
6. Open **Reports** and show the generated security assessment report; download it only if needed.
7. Open **Security Activity** to show authentication, demo setup, and application audit events.
8. Open **AI Assistant**, select a finding ID, and demonstrate the existing grounded explanation/remediation fallback.
9. Open **Alerts** and show the seeded open alert.
10. Return to the dashboard for the final overview.

## Troubleshooting

- **Backend does not start:** confirm `backend\.venv` exists and the selected port is unused.
- **Frontend cannot reach the API:** confirm `VITE_API_BASE_URL` includes `/api/v1` and matches the backend host/port.
- **Database is not ready:** confirm the backend process is running and inspect `/ready`; the demo uses only `.demo\cybershield-demo.db`.
- **Data is missing:** stop the backend, run `scripts\reset-demo.ps1`, and start it again with `DEMO_PASSWORD` set.
- **Report generation fails:** confirm the `.demo\reports` directory is writable.
- **Authentication fails:** use the current `DEMO_EMAIL` and the same temporary `DEMO_PASSWORD` used to seed the database.

The demo is local and synthetic. It does not claim public deployment, external-service availability, production traffic, or production-scale performance.
