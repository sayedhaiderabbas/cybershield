$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BackendRoot = Join-Path $ProjectRoot 'backend'
$FrontendRoot = Join-Path $ProjectRoot 'frontend'
$DemoRoot = Join-Path $ProjectRoot '.demo'

New-Item -ItemType Directory -Path $DemoRoot -Force | Out-Null
$env:APP_ENV = 'development'
$env:HOST = if ($env:HOST) { $env:HOST } else { '0.0.0.0' }
$env:PORT = if ($env:PORT) { $env:PORT } else { '5000' }
$env:DATABASE_URL = if ($env:DATABASE_URL) { $env:DATABASE_URL } else { "sqlite:///$DemoRoot/cybershield-demo.db" }
$env:REPORT_STORAGE_ROOT = if ($env:REPORT_STORAGE_ROOT) { $env:REPORT_STORAGE_ROOT } else { (Join-Path $DemoRoot 'reports') }
$env:CORS_ORIGINS = if ($env:CORS_ORIGINS) { $env:CORS_ORIGINS } else { '["http://127.0.0.1:4173","http://localhost:4173"]' }
$env:JWT_SECRET = if ($env:JWT_SECRET) { $env:JWT_SECRET } else { 'replace-with-a-local-demo-secret-at-least-32-characters' }

if (-not $env:DEMO_PASSWORD) {
    throw 'Set DEMO_PASSWORD to a temporary local password of at least 12 characters before starting the demo.'
}
$env:DEMO_EMAIL = if ($env:DEMO_EMAIL) { $env:DEMO_EMAIL } else { 'demo@example.invalid' }

Push-Location $BackendRoot
try {
    & '.\.venv\Scripts\python.exe' '.\scripts\seed_demo.py'
    if ($LASTEXITCODE -ne 0) { throw 'Demo data seeding failed.' }
    Write-Host "Backend: http://$($env:HOST):$($env:PORT)"
    Write-Host "Health:  http://$($env:HOST):$($env:PORT)/health"
    Write-Host "Ready:   http://$($env:HOST):$($env:PORT)/ready"
    Write-Host 'Start the frontend in a second terminal with:'
    Write-Host '  $env:VITE_API_BASE_URL="http://127.0.0.1:5000/api/v1"; npm run build; npm run preview -- --host 0.0.0.0 --port 4173'
    & '.\.venv\Scripts\python.exe' '-m' 'uvicorn' 'app.main:app' '--host' $env:HOST '--port' $env:PORT
}
finally {
    Pop-Location
}
