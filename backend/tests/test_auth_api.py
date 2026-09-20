from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import get_settings
from app.models.entities import User
from conftest import TestingSessionLocal


def _register_user(client, *, email: str = 'owner@example.com', password: str = 'SecurePassword123', full_name: str = 'Owner User') -> dict:
    response = client.post(
        '/api/v1/auth/register',
        json={'email': email, 'password': password, 'full_name': full_name},
    )
    assert response.status_code == 201, response.text
    return response.json()['data']


def test_registration_and_login(client) -> None:
    user = _register_user(client, email='auth-user@example.com')
    assert user['email'] == 'auth-user@example.com'
    assert 'password' not in user

    login_response = client.post(
        '/api/v1/auth/login',
        json={'email': 'auth-user@example.com', 'password': 'SecurePassword123'},
    )
    assert login_response.status_code == 200, login_response.text
    payload = login_response.json()['data']
    assert payload['token_type'] == 'bearer'
    assert payload['user']['email'] == 'auth-user@example.com'

    me_response = client.get('/api/v1/auth/me', headers={'Authorization': f"Bearer {payload['token']}"})
    assert me_response.status_code == 200, me_response.text
    assert me_response.json()['data']['id'] == payload['user']['id']


def test_duplicate_email_and_login_rejection(client) -> None:
    _register_user(client, email='duplicate@example.com')

    duplicate_response = client.post(
        '/api/v1/auth/register',
        json={'email': 'duplicate@example.com', 'password': 'AnotherSecurePassword123', 'full_name': 'Duplicate User'},
    )
    assert duplicate_response.status_code == 409, duplicate_response.text

    bad_login = client.post(
        '/api/v1/auth/login',
        json={'email': 'duplicate@example.com', 'password': 'wrongPassword123'},
    )
    assert bad_login.status_code == 401, bad_login.text
    assert bad_login.json()['error']['code'] == 'AUTHENTICATION_FAILED'


def test_token_and_inactive_user_validation(client) -> None:
    settings = get_settings()
    expired_payload = {
        'sub': 'unknown-user',
        'iat': int(datetime.now(timezone.utc).timestamp()) - 120,
        'exp': int(datetime.now(timezone.utc).timestamp()) - 10,
        'type': 'access',
    }
    expired_token = jwt.encode(expired_payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)

    expired_response = client.get('/api/v1/auth/me', headers={'Authorization': f'Bearer {expired_token}'})
    assert expired_response.status_code == 401, expired_response.text

    user_record = _register_user(client, email='inactive@example.com')
    db = TestingSessionLocal()
    try:
        user = db.query(User).filter_by(email='inactive@example.com').one()
        user.is_active = False
        db.commit()
    finally:
        db.close()

    inactive_login = client.post(
        '/api/v1/auth/login',
        json={'email': 'inactive@example.com', 'password': 'SecurePassword123'},
    )
    assert inactive_login.status_code == 401, inactive_login.text

    active_token = client.post('/api/v1/auth/login', json={'email': 'inactive@example.com', 'password': 'SecurePassword123'}).json()
    assert active_token['error']['code'] == 'AUTHENTICATION_FAILED'


def test_cross_user_business_access_is_rejected(client) -> None:
    user_a = _register_user(client, email='usera@example.com', full_name='User A')
    user_b = _register_user(client, email='userb@example.com', full_name='User B')

    token_a = client.post('/api/v1/auth/login', json={'email': 'usera@example.com', 'password': 'SecurePassword123'}).json()['data']['token']
    token_b = client.post('/api/v1/auth/login', json={'email': 'userb@example.com', 'password': 'SecurePassword123'}).json()['data']['token']

    business_a = client.post(
        '/api/v1/businesses',
        json={'name': 'Business A', 'industry': 'Technology'},
        headers={'Authorization': f'Bearer {token_a}'},
    )
    assert business_a.status_code == 201, business_a.text
    business_b = client.post(
        '/api/v1/businesses',
        json={'name': 'Business B', 'industry': 'Retail'},
        headers={'Authorization': f'Bearer {token_b}'},
    )
    assert business_b.status_code == 201, business_b.text

    cross_user = client.get(
        f"/api/v1/businesses/{business_b.json()['data']['id']}",
        headers={'Authorization': f'Bearer {token_a}'},
    )
    assert cross_user.status_code in {403, 404}, cross_user.text
