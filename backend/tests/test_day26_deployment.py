from __future__ import annotations

from pathlib import Path

from app.core.config import Settings
from app.services.report_service import REPORT_STORAGE_ROOT


def test_production_settings_require_explicit_secure_configuration() -> None:
    settings = Settings(
        APP_ENV='production',
        DATABASE_URL='sqlite:///./isolated-production.db',
        JWT_SECRET='a-secure-production-secret-that-is-long-enough',
        CORS_ORIGINS=['https://app.example.test'],
        REPORT_STORAGE_ROOT='/srv/cybershield/reports',
    )

    assert settings.app_env == 'production'
    assert settings.report_storage_root == '/srv/cybershield/reports'
    assert settings.cors_allowlist == ['https://app.example.test']


def test_report_storage_root_is_portable_and_not_repository_absolute() -> None:
    assert isinstance(REPORT_STORAGE_ROOT, Path)
    assert REPORT_STORAGE_ROOT.name == 'generated'


def test_readiness_checks_database(client) -> None:
    response = client.get('/ready')

    assert response.status_code == 200
    assert response.json() == {'status': 'ready'}
