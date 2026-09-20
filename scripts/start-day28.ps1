$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BackendRoot = Join-Path $ProjectRoot 'backend'
$FrontendRoot = Join-Path $ProjectRoot 'frontend'
$DemoRoot = Join-Path $ProjectRoot '.day28'
$Caddyfile = Join-Path $ProjectRoot 'deployment\caddy\Caddyfile'

if (-not (Get-Command caddy -ErrorAction SilentlyContinue)) {
    throw 'Caddy is required for the Day 28 local TLS workflow. Install Caddy separately and ensure caddy.exe is on PATH.'
}
if (-not $env:DAY28_PASSWORD) {
    throw 'Set DAY28_PASSWORD to a temporary local password of at least 12 characters before starting Day 28.'
}
if (-not $env:DAY28_JWT_SECRET -or $env:DAY28_JWT_SECRET.Length -lt 32) {
    throw 'Set DAY28_JWT_SECRET to a random value of at least 32 characters before starting Day 28.'
}

New-Item -ItemType Directory -Path $DemoRoot -Force | Out-Null
$env:APP_ENV = 'production'
$env:HOST = '127.0.0.1'
$env:PORT = '5058'
$env:DATABASE_URL = "sqlite:///$DemoRoot/cybershield-day28.db"
$env:REPORT_STORAGE_ROOT = Join-Path $DemoRoot 'reports'
$env:CORS_ORIGINS = '["https://localhost:8443"]'
$env:JWT_SECRET = $env:DAY28_JWT_SECRET
$env:DEMO_PASSWORD = $env:DAY28_PASSWORD
$env:DEMO_EMAIL = if ($env:DAY28_EMAIL) { $env:DAY28_EMAIL } else { 'demo@example.invalid' }

Push-Location $BackendRoot
try {
    & '.\.venv\Scripts\python.exe' '.\scripts\seed_demo.py'
    if ($LASTEXITCODE -ne 0) { throw 'Day 28 demo data seeding failed.' }
} finally {
    Pop-Location
}

Push-Location $FrontendRoot
try {
    $env:VITE_API_BASE_URL = '/api/v1'
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'Day 28 frontend production build failed.' }
} finally {
    Pop-Location
}

$backend = Start-Process -FilePath (Join-Path $BackendRoot '.venv\Scripts\python.exe') `
    -ArgumentList '-m','uvicorn','app.main:app','--host','127.0.0.1','--port','5058','--proxy-headers','--forwarded-allow-ips','127.0.0.1' `
    -WorkingDirectory $BackendRoot -PassThru
try {
    Write-Host "Backend PID: $($backend.Id)"
    Write-Host 'HTTP redirect:  http://localhost:8080'
    Write-Host 'HTTPS frontend: https://localhost:8443'
    Write-Host 'Caddy uses a local internal certificate; browser trust warnings are expected.'
    Push-Location $ProjectRoot
    try {
        caddy run --config $Caddyfile
    } finally {
        Pop-Location
    }
} finally {
    if (-not $backend.HasExited) {
        Stop-Process -Id $backend.Id -Force
    }
}
