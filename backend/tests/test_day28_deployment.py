from pathlib import Path

from app.core.config import Settings


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DAY28_CADDYFILE = PROJECT_ROOT / 'deployment' / 'caddy' / 'Caddyfile'


def test_day28_production_settings_allow_only_explicit_https_origin() -> None:
    settings = Settings(
        APP_ENV='production',
        DATABASE_URL='sqlite:///./isolated-day28.db',
        JWT_SECRET='a-day28-production-secret-that-is-long-enough',
        CORS_ORIGINS=['https://localhost:8443'],
        REPORT_STORAGE_ROOT='/srv/cybershield/reports',
    )

    assert settings.cors_allowlist == ['https://localhost:8443']


def test_day28_caddy_routes_tls_frontend_and_backend() -> None:
    caddyfile = DAY28_CADDYFILE.read_text(encoding='utf-8')

    assert 'tls internal' in caddyfile
    assert 'redir https://localhost:8443{uri} permanent' in caddyfile
    assert 'reverse_proxy 127.0.0.1:5058' in caddyfile
    assert 'root * frontend/dist' in caddyfile


def test_day28_caddyfile_does_not_contain_production_secrets() -> None:
    caddyfile = DAY28_CADDYFILE.read_text(encoding='utf-8')

    assert 'JWT_SECRET' not in caddyfile
    assert 'PASSWORD' not in caddyfile
    assert 'BEGIN PRIVATE KEY' not in caddyfile
