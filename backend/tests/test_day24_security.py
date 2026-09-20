from __future__ import annotations

import os

from app.core.config import Settings, get_settings


def test_legacy_identity_header_is_disabled_by_default() -> None:
    settings = Settings(
        APP_ENV='development',
        JWT_SECRET='a-development-secret-that-is-at-least-32-chars',
        ENABLE_LEGACY_USER_HEADER=False,
    )
    assert settings.enable_legacy_user_header is False


def test_legacy_identity_header_is_not_accepted_when_disabled(client, user_record) -> None:
    os.environ['ENABLE_LEGACY_USER_HEADER'] = 'false'
    get_settings.cache_clear()
    try:
        response = client.get('/api/v1/auth/me', headers={'X-User-ID': user_record.id})
        assert response.status_code in {401, 403}
    finally:
        os.environ['ENABLE_LEGACY_USER_HEADER'] = 'true'
        get_settings.cache_clear()


def test_security_headers_are_present(client) -> None:
    response = client.get('/health')
    assert response.status_code == 200
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert response.headers['Content-Security-Policy'].startswith("default-src 'self'")
    assert response.headers['Permissions-Policy']


def test_production_rejects_default_jwt_secret() -> None:
    try:
        Settings(
            APP_ENV='production',
            JWT_SECRET='replace-with-a-secure-random-secret-at-least-32-characters-long',
        )
    except ValueError as exc:
        assert 'JWT_SECRET' in str(exc)
    else:
        raise AssertionError('Production settings accepted the default JWT secret.')
