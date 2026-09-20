from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models.entities import Business, User, Website
from app.schemas import MonitoringTargetCreate
from app.services.monitoring_service import MonitoringService
from conftest import TestingSessionLocal


def _register_and_login(client, *, email: str, password: str = 'SecurePassword123', full_name: str = 'Owner User') -> str:
    client.post('/api/v1/auth/register', json={'email': email, 'password': password, 'full_name': full_name})
    login = client.post('/api/v1/auth/login', json={'email': email, 'password': password})
    assert login.status_code == 200, login.text
    return login.json()['data']['token']


def test_monitoring_crud_and_ownership(client) -> None:
    owner_token = _register_and_login(client, email='monitor-owner@example.com')
    other_token = _register_and_login(client, email='monitor-other@example.com')

    business = client.post('/api/v1/businesses', json={'name': 'Monitor Business', 'industry': 'Security'}, headers={'Authorization': f'Bearer {owner_token}'})
    business_id = business.json()['data']['id']

    website = client.post(
        '/api/v1/websites',
        json={'business_id': business_id, 'name': 'ACME Site', 'url': 'https://example.com'},
        headers={'Authorization': f'Bearer {owner_token}'},
    )
    website_id = website.json()['data']['id']

    create = client.post(
        '/api/v1/monitoring',
        json={'business_id': business_id, 'website_id': website_id, 'schedule': 'daily'},
        headers={'Authorization': f'Bearer {owner_token}'},
    )
    assert create.status_code == 201, create.text
    target = create.json()['data']
    assert target['schedule'] == 'daily'
    assert target['enabled'] is True

    list_response = client.get('/api/v1/monitoring', headers={'Authorization': f'Bearer {owner_token}'})
    assert list_response.status_code == 200, list_response.text
    assert len(list_response.json()['data']) == 1

    patch_response = client.patch(
        f"/api/v1/monitoring/{target['id']}",
        json={'enabled': False},
        headers={'Authorization': f'Bearer {owner_token}'},
    )
    assert patch_response.status_code == 200, patch_response.text
    assert patch_response.json()['data']['enabled'] is False

    forbidden = client.get(
        f"/api/v1/monitoring/{target['id']}",
        headers={'Authorization': f'Bearer {other_token}'},
    )
    assert forbidden.status_code in {403, 404}, forbidden.text

    duplicate = client.post(
        '/api/v1/monitoring',
        json={'business_id': business_id, 'website_id': website_id, 'schedule': 'weekly'},
        headers={'Authorization': f'Bearer {owner_token}'},
    )
    assert duplicate.status_code == 409, duplicate.text


def test_monitoring_scheduler_marks_due_targets_and_history() -> None:
    db = TestingSessionLocal()
    try:
        owner = User(email='scheduler-owner@example.com', password_hash='hash', full_name='Scheduler Owner', is_active=True)
        db.add(owner)
        db.commit()
        db.refresh(owner)

        business = Business(owner_id=owner.id, name='Scheduler Business', industry='Technology')
        db.add(business)
        db.commit()
        db.refresh(business)

        website = Website(
            business_id=business.id,
            name='Scheduler Website',
            url='https://example.test',
            normalized_url='https://example.test',
            hostname='example.test',
            status='active',
        )
        db.add(website)
        db.commit()
        db.refresh(website)

        target = MonitoringService(db).create(
            owner.id,
            MonitoringTargetCreate(business_id=business.id, website_id=website.id, schedule='daily', enabled=True),
        )
        target.enabled = True
        target.next_check_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        target.last_check_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db.commit()

        due = MonitoringService(db).get_due_targets()
        assert any(item.id == target.id for item in due)
        history = MonitoringService(db).get_history(target.id, owner.id)
        assert isinstance(history, list)
    finally:
        db.close()
