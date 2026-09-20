from __future__ import annotations

from app.models.entities import Business, User, Website
from app.services.audit_service import AuditEventService
from conftest import TestingSessionLocal


def _register_and_login(client, *, email: str, password: str = 'SecurePassword123') -> str:
    client.post('/api/v1/auth/register', json={'email': email, 'password': password, 'full_name': 'Audit User'})
    response = client.post('/api/v1/auth/login', json={'email': email, 'password': password})
    assert response.status_code == 200, response.text
    return response.json()['data']['token']


def test_audit_events_are_created_and_filterable(client) -> None:
    token = _register_and_login(client, email='audit-owner@example.com')
    db = TestingSessionLocal()
    try:
        user = db.query(User).filter_by(email='audit-owner@example.com').one()
        business = Business(owner_id=user.id, name='Audit Business', industry='Technology')
        db.add(business)
        db.commit(); db.refresh(business)

        create_response = client.post(
            '/api/v1/websites',
            json={'business_id': business.id, 'name': 'Audit Site', 'url': 'https://audit.example.com'},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert create_response.status_code == 201, create_response.text

        response = client.get(
            '/api/v1/audit-events',
            params={'event_type': 'WEBSITE', 'resource_type': 'website'},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload['meta']['total'] >= 1
        assert any(item['action'] == 'WEBSITE_CREATED' for item in payload['data'])
    finally:
        db.close()


def test_audit_api_requires_authentication_and_blocks_cross_business_access(client) -> None:
    first_token = _register_and_login(client, email='audit-a@example.com')
    second_token = _register_and_login(client, email='audit-b@example.com')

    db = TestingSessionLocal()
    try:
        a_user = db.query(User).filter_by(email='audit-a@example.com').one()
        b_user = db.query(User).filter_by(email='audit-b@example.com').one()
        a_business = Business(owner_id=a_user.id, name='Business A', industry='Tech')
        db.add(a_business); db.commit(); db.refresh(a_business)
        b_business = Business(owner_id=b_user.id, name='Business B', industry='Tech')
        db.add(b_business); db.commit(); db.refresh(b_business)

        AuditEventService(db).record_event(
            event_type='BUSINESS',
            action='BUSINESS_CREATED',
            message='Business created',
            actor_user_id=a_user.id,
            business_id=a_business.id,
            resource_type='business',
            resource_id=a_business.id,
            outcome='SUCCESS',
            severity='info',
            request_id='trace-1',
        )
        AuditEventService(db).record_event(
            event_type='BUSINESS',
            action='BUSINESS_CREATED',
            message='Business created',
            actor_user_id=b_user.id,
            business_id=b_business.id,
            resource_type='business',
            resource_id=b_business.id,
            outcome='SUCCESS',
            severity='info',
            request_id='trace-2',
        )
        db.commit()

        unauthenticated = client.get('/api/v1/audit-events')
        assert unauthenticated.status_code == 401

        allowed = client.get('/api/v1/audit-events', headers={'Authorization': f'Bearer {first_token}'})
        assert allowed.status_code == 200
        assert all(item['business_id'] == a_business.id for item in allowed.json()['data'] if item['business_id'])

        forbidden = client.get('/api/v1/audit-events', headers={'Authorization': f'Bearer {second_token}'})
        assert forbidden.status_code == 200
        assert not any(item['business_id'] == a_business.id for item in forbidden.json()['data'])
    finally:
        db.close()


def test_audit_sanitization_redacts_sensitive_values() -> None:
    db = TestingSessionLocal()
    try:
        safe_event = AuditEventService(db).record_event(
            event_type='AUTHENTICATION',
            action='LOGIN_FAILURE',
            message='Failed login.',
            actor_user_id=None,
            resource_type='auth',
            resource_id='login',
            outcome='FAILURE',
            metadata={'password': 'secret', 'authorization': 'Bearer abc', 'token': 'abc', 'safe': 'ok'},
        )
        assert 'password' not in (safe_event.event_details or '')
        assert 'secret' not in (safe_event.event_details or '')
        assert 'Bearer abc' not in (safe_event.event_details or '')
        assert 'ok' in (safe_event.event_details or '')
    finally:
        db.close()
