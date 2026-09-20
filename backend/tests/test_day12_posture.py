from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models.entities import Alert, Business, Finding, MonitoringTarget, Scan, Website
from conftest import TestingSessionLocal


def _register_and_login(client, *, email: str, password: str = 'SecurePassword123', full_name: str = 'Owner User') -> tuple[str, str]:
    registration = client.post('/api/v1/auth/register', json={'email': email, 'password': password, 'full_name': full_name})
    assert registration.status_code == 201, registration.text
    login = client.post('/api/v1/auth/login', json={'email': email, 'password': password})
    assert login.status_code == 200, login.text
    payload = login.json()['data']
    return payload['token'], payload['user']['id']


def _create_business_and_website(client, token: str, *, business_name: str = 'Business One', website_name: str = 'Website One', website_url: str = 'https://example.com') -> tuple[str, str]:
    business = client.post('/api/v1/businesses', json={'name': business_name, 'industry': 'Technology'}, headers={'Authorization': f'Bearer {token}'})
    assert business.status_code == 201, business.text
    business_id = business.json()['data']['id']
    website = client.post('/api/v1/websites', json={'business_id': business_id, 'name': website_name, 'url': website_url}, headers={'Authorization': f'Bearer {token}'})
    assert website.status_code == 201, website.text
    return business_id, website.json()['data']['id']


def test_security_posture_summary_and_authorization(client) -> None:
    owner_token, owner_id = _register_and_login(client, email='posture-owner@example.com')
    other_token, _ = _register_and_login(client, email='posture-other@example.com')
    business_id, website_id = _create_business_and_website(client, owner_token, business_name='Owner Business', website_name='Owner Website')

    db = TestingSessionLocal()
    try:
        now = datetime.now(timezone.utc)
        previous_scan = Scan(
            website_id=website_id,
            status='completed',
            scan_type='monitoring',
            risk_score=42.0,
            completed_at=now - timedelta(days=1),
            created_at=now - timedelta(days=1),
        )
        current_scan = Scan(
            website_id=website_id,
            status='completed',
            scan_type='monitoring',
            risk_score=61.0,
            completed_at=now,
            created_at=now,
        )
        db.add_all([previous_scan, current_scan])
        db.commit()
        db.refresh(previous_scan)
        db.refresh(current_scan)

        monitoring = MonitoringTarget(
            business_id=business_id,
            website_id=website_id,
            enabled=True,
            schedule='daily',
            interval_minutes=1440,
            next_check_at=now + timedelta(days=1),
            failure_count=1,
        )
        db.add(monitoring)
        db.commit()
        db.refresh(monitoring)

        critical_finding = Finding(
            scan_id=current_scan.id,
            website_id=website_id,
            title='Critical certificate weakness',
            slug='critical-certificate-weakness',
            fingerprint=f'{website_id}:CRT-CRITICAL:tls',
            severity='critical',
            priority='immediate',
            category='tls',
            status='open',
            description='Certificate validation is weak.',
            evidence='[]',
            recommendation='Update certificate settings.',
            references='CRT-CRITICAL',
            first_seen_at=now,
            last_seen_at=now,
            occurrence_count=1,
        )
        high_finding = Finding(
            scan_id=current_scan.id,
            website_id=website_id,
            title='Missing HSTS',
            slug='missing-hsts',
            fingerprint=f'{website_id}:HSTS-004:security_headers',
            severity='high',
            priority='high',
            category='security_headers',
            status='acknowledged',
            description='HSTS is missing.',
            evidence='[]',
            recommendation='Add HSTS headers.',
            references='HSTS-004',
            first_seen_at=now,
            last_seen_at=now,
            occurrence_count=1,
        )
        resolved_finding = Finding(
            scan_id=previous_scan.id,
            website_id=website_id,
            title='Resolved cookie issue',
            slug='resolved-cookie-issue',
            fingerprint=f'{website_id}:COOKIE-099:cookie_security',
            severity='low',
            priority='low',
            category='cookie_security',
            status='resolved',
            description='Cookie issue was resolved.',
            evidence='[]',
            recommendation='Keep cookie settings secure.',
            references='COOKIE-099',
            first_seen_at=now - timedelta(days=2),
            last_seen_at=now - timedelta(days=2),
            occurrence_count=1,
            resolved_at=now,
        )
        db.add_all([critical_finding, high_finding, resolved_finding])
        db.commit()

        db.add_all([
            Alert(
                business_id=business_id,
                website_id=website_id,
                monitoring_id=monitoring.id,
                scan_id=current_scan.id,
                finding_id=critical_finding.id,
                alert_type='NEW_CRITICAL_FINDING',
                severity='critical',
                title='Critical finding detected',
                message='Critical finding detected.',
                status='open',
                deduplication_key=f'{business_id}:{website_id}:NEW_CRITICAL_FINDING:{current_scan.id}:{critical_finding.id}',
                alert_metadata='{"finding_id": "'+critical_finding.id+'"}',
            ),
            Alert(
                business_id=business_id,
                website_id=website_id,
                monitoring_id=monitoring.id,
                scan_id=current_scan.id,
                alert_type='MONITORING_FAILURE',
                severity='medium',
                title='Scheduled security assessment could not be completed.',
                message='Scheduled security assessment could not be completed.',
                status='open',
                deduplication_key=f'{business_id}:{website_id}:MONITORING_FAILURE:{monitoring.id}:failed',
                alert_metadata='{"monitoring_id": "'+monitoring.id+'"}',
            ),
        ])
        db.commit()

        response = client.get('/api/v1/security/posture', headers={'Authorization': f'Bearer {owner_token}'})
        assert response.status_code == 200, response.text
        data = response.json()['data']
        assert data['summary']['risk_score'] == 61
        assert data['summary']['previous_risk_score'] == 42
        assert data['summary']['risk_delta'] == 19
        assert data['findings']['open'] == 2
        assert data['findings']['critical'] == 1
        assert data['findings']['high'] == 1
        assert data['alerts']['critical'] == 1
        assert data['alerts']['monitoring_failures'] == 1
        assert data['monitoring']['active_targets'] == 1
        assert data['monitoring']['failed_assessments'] == 1
        assert data['trends']['status'] in {'available', 'limited-history'}
        assert any(priority['source_type'] == 'finding' for priority in data['priorities'])
        assert any(priority['source_type'] == 'monitoring' for priority in data['priorities'])

        other_response = client.get('/api/v1/security/posture', headers={'Authorization': f'Bearer {other_token}'})
        assert other_response.status_code == 200, other_response.text
        assert other_response.json()['data']['findings']['open'] == 0

    finally:
        db.close()


def test_security_posture_empty_state_and_no_history(client) -> None:
    token, _ = _register_and_login(client, email='posture-empty@example.com')
    business_id, website_id = _create_business_and_website(client, token, business_name='Empty Business', website_name='Empty Website')

    response = client.get('/api/v1/security/posture', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200, response.text
    data = response.json()['data']
    assert data['summary']['risk_score'] == 0
    assert data['findings']['open'] == 0
    assert data['alerts']['total_open'] == 0
    assert data['monitoring']['active_targets'] == 0
    assert data['trends']['status'] == 'no-data'
    assert 'No websites are currently monitored' in data['executive_summary']

    unauthorized = client.get('/api/v1/security/posture')
    assert unauthorized.status_code == 401, unauthorized.text
