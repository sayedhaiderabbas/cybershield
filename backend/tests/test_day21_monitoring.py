from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models.entities import Business, Finding, Scan, Website
from conftest import TestingSessionLocal


def _register_and_login(client, email: str) -> tuple[str, str]:
    client.post('/api/v1/auth/register', json={'email': email, 'password': 'SecurePassword123', 'full_name': 'Monitoring Owner'})
    login = client.post('/api/v1/auth/login', json={'email': email, 'password': 'SecurePassword123'})
    assert login.status_code == 200, login.text
    return login.json()['data']['token'], login.json()['data']['user']['id']


def _fixture(db, owner_id: str) -> tuple[Business, Website]:
    business = Business(owner_id=owner_id, name=f'Monitor {owner_id[:6]}', industry='Technology')
    db.add(business)
    db.flush()
    website = Website(
        business_id=business.id,
        name='Monitored site',
        url='https://monitor.example',
        normalized_url='https://monitor.example',
        hostname='monitor.example',
        status='active',
    )
    db.add(website)
    db.commit()
    db.refresh(business)
    db.refresh(website)
    return business, website


def test_day21_overview_is_authenticated_and_business_scoped(client) -> None:
    owner_token, owner_id = _register_and_login(client, 'day21-owner@example.com')
    other_token, other_id = _register_and_login(client, 'day21-other@example.com')
    db = TestingSessionLocal()
    try:
        owner_business, owner_website = _fixture(db, owner_id)
        other_business, other_website = _fixture(db, other_id)
        owner_monitoring = client.post(
            '/api/v1/monitoring',
            json={'business_id': owner_business.id, 'website_id': owner_website.id},
            headers={'Authorization': f'Bearer {owner_token}'},
        )
        assert owner_monitoring.status_code == 201
        other_monitoring = client.post(
            '/api/v1/monitoring',
            json={'business_id': other_business.id, 'website_id': other_website.id},
            headers={'Authorization': f'Bearer {other_token}'},
        )
        assert other_monitoring.status_code == 201

        assert client.get('/api/v1/monitoring/overview').status_code in {401, 403}
        overview = client.get('/api/v1/monitoring/overview', headers={'Authorization': f'Bearer {owner_token}'})
        assert overview.status_code == 200
        assert len(overview.json()['data']) == 1
        item = overview.json()['data'][0]
        assert item['website_id'] == owner_website.id
        assert item['business_id'] == owner_business.id
        assert 'last_error' in item
    finally:
        db.close()


def test_day21_overview_and_history_use_authoritative_scan_state(client) -> None:
    token, owner_id = _register_and_login(client, 'day21-state@example.com')
    db = TestingSessionLocal()
    try:
        business, website = _fixture(db, owner_id)
        first = Scan(website_id=website.id, status='completed', scan_type='monitoring', risk_score=31, completed_at=datetime.now(timezone.utc) - timedelta(days=1))
        second = Scan(website_id=website.id, status='completed', scan_type='monitoring', risk_score=47, completed_at=datetime.now(timezone.utc))
        db.add_all([first, second])
        db.flush()
        db.add(Finding(
            scan_id=second.id,
            website_id=website.id,
            title='Current finding',
            slug='current-finding',
            fingerprint='day21-current',
            severity='high',
            category='headers',
            status='open',
            description='Current finding.',
            evidence='api_key=synthetic-day21-secret',
            recommendation='Remediate.',
        ))
        db.commit()
        monitoring = client.post(
            '/api/v1/monitoring',
            json={'business_id': business.id, 'website_id': website.id},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert monitoring.status_code == 201
        target_id = monitoring.json()['data']['id']

        overview = client.get('/api/v1/monitoring/overview', headers={'Authorization': f'Bearer {token}'})
        item = overview.json()['data'][0]
        assert item['current_risk_score'] == 47
        assert item['previous_risk_score'] == 31
        assert item['risk_delta'] == 16
        assert item['findings_count'] == 1
        assert item['open_finding_count'] == 1

        history = client.get(f'/api/v1/monitoring/{target_id}/history?page=1&page_size=1', headers={'Authorization': f'Bearer {token}'})
        assert history.status_code == 200
        assert len(history.json()['data']) == 1
        assert history.json()['meta']['total'] == 2
        assert history.json()['meta']['total_pages'] == 2
        assert history.json()['data'][0]['risk_delta'] == 16
        changes = client.get(f'/api/v1/monitoring/{target_id}/changes', headers={'Authorization': f'Bearer {token}'})
        assert changes.status_code == 200
        assert 'synthetic-day21-secret' not in changes.text
    finally:
        db.close()
