from __future__ import annotations

import uuid

from app.models.entities import Business, Finding, Scan, Website
from app.scanner.engine import ScannerEngine
from app.scanner.models import CheckResult
from app.services.risk_service import RiskService
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


def test_finding_status_lifecycle_and_mass_assignment_guard(client) -> None:
    token, _ = _register_and_login(client, email='lifecycle@example.com')
    _, website_id = _create_business_and_website(client, token)

    db = TestingSessionLocal()
    try:
        scan = Scan(website_id=website_id, status='completed', scan_type='baseline')
        db.add(scan)
        db.commit()
        db.refresh(scan)

        finding = Finding(
            scan_id=scan.id,
            website_id=website_id,
            title='Missing HSTS',
            slug='missing-hsts',
            fingerprint=f'{website_id}:CS-HSTS-001:security_headers',
            severity='high',
            priority='high',
            category='security_headers',
            status='open',
            description='The HTTPS response does not include HSTS.',
            evidence='[]',
            recommendation='Add a Strict-Transport-Security header.',
            references='CS-HSTS-001',
            first_seen_at=scan.created_at,
            last_seen_at=scan.created_at,
            occurrence_count=1,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)

        response = client.patch(f'/api/v1/findings/{finding.id}', json={'status': 'acknowledged'}, headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200, response.text
        assert response.json()['data']['status'] == 'acknowledged'

        response = client.patch(f'/api/v1/findings/{finding.id}', json={'status': 'resolved'}, headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200, response.text
        assert response.json()['data']['status'] == 'resolved'

        invalid = client.patch(f'/api/v1/findings/{finding.id}', json={'status': 'archived'}, headers={'Authorization': f'Bearer {token}'})
        assert invalid.status_code == 422, invalid.text

        blocked = client.patch(
            f'/api/v1/findings/{finding.id}',
            json={'severity': 'critical', 'risk_score': 100, 'website_id': 'another-id', 'scan_id': 'another-id'},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert blocked.status_code == 422, blocked.text
    finally:
        db.close()


def test_same_finding_across_scans_is_deduplicated(client) -> None:
    token, _ = _register_and_login(client, email='dedup@example.com')
    _, website_id = _create_business_and_website(client, token)

    db = TestingSessionLocal()
    try:
        website = db.query(Website).filter_by(id=website_id).one()
        engine = ScannerEngine(db)
        scan_one = Scan(website_id=website_id, status='completed', scan_type='baseline')
        scan_two = Scan(website_id=website_id, status='completed', scan_type='baseline')
        db.add_all([scan_one, scan_two])
        db.commit()
        db.refresh(scan_one)
        db.refresh(scan_two)

        result = CheckResult(
            check_id='CS-HSTS-001',
            title='Missing HSTS',
            category='security_headers',
            severity='medium',
            description='HSTS is missing.',
            evidence={'header': 'Strict-Transport-Security'},
            recommendation='Add HSTS.',
        )

        engine._persist_finding(scan_one, website, result)
        engine._persist_finding(scan_two, website, result)
        db.commit()

        findings = db.query(Finding).filter_by(website_id=website_id, fingerprint=f'{website_id}:CS-HSTS-001:security_headers').all()
        assert len(findings) == 1
        assert findings[0].occurrence_count >= 2
        assert findings[0].last_seen_at is not None
        assert findings[0].scan_id == scan_two.id
    finally:
        db.close()


def test_security_overview_and_finding_list_are_owner_safe(client) -> None:
    owner_token, owner_id = _register_and_login(client, email='owneroverview@example.com')
    other_token, _ = _register_and_login(client, email='otherview@example.com')
    _, website_id = _create_business_and_website(client, owner_token, business_name='Owner Business', website_name='Owner Website')

    db = TestingSessionLocal()
    try:
        scan = Scan(website_id=website_id, status='completed', scan_type='baseline')
        db.add(scan)
        db.commit()
        db.refresh(scan)

        finding = Finding(
            scan_id=scan.id,
            website_id=website_id,
            title='Weak TLS settings',
            slug='weak-tls-settings',
            fingerprint=f'{website_id}:CS-TLS-001:tls',
            severity='high',
            priority='high',
            category='tls',
            status='open',
            description='TLS settings are weak.',
            evidence='[]',
            recommendation='Harden TLS configuration.',
            references='CS-TLS-001',
            first_seen_at=scan.created_at,
            last_seen_at=scan.created_at,
            occurrence_count=1,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)

        overview = RiskService(db).overview_for_user(owner_id)
        assert overview['risk_model_version'] == '1.0'
        assert overview['open_finding_count'] >= 1
        assert overview['severity_counts']['high'] >= 1
    finally:
        db.close()

    overview_response = client.get('/api/v1/security/overview', headers={'Authorization': f'Bearer {owner_token}'})
    assert overview_response.status_code == 200, overview_response.text
    overview_payload = overview_response.json()['data']
    assert overview_payload['risk_model_version'] == '1.0'
    assert overview_payload['open_finding_count'] >= 1
    assert overview_payload['severity_counts']['high'] >= 1

    other_overview = client.get('/api/v1/security/overview', headers={'Authorization': f'Bearer {other_token}'})
    assert other_overview.status_code == 200, other_overview.text
    assert other_overview.json()['data']['open_finding_count'] == 0

    findings = client.get('/api/v1/findings', params={'severity': 'high', 'status': 'open', 'page_size': 10}, headers={'Authorization': f'Bearer {owner_token}'})
    assert findings.status_code == 200, findings.text
    assert findings.json()['meta']['total'] >= 1


def test_risk_service_deterministic_formula_and_version(client) -> None:
    token, owner_id = _register_and_login(client, email='risk@example.com')
    _, website_id = _create_business_and_website(client, token, business_name='Risk Business', website_name='Risk Website')

    db = TestingSessionLocal()
    try:
        scan = Scan(website_id=website_id, status='completed', scan_type='baseline')
        db.add(scan)
        db.commit()
        db.refresh(scan)

        entries = [
            Finding(
                scan_id=scan.id,
                website_id=website_id,
                title='Low issue',
                slug='low-issue',
                fingerprint=f'{website_id}:L1:tls',
                severity='low',
                priority='low',
                category='tls',
                status='open',
                description='Low issue',
                evidence='[]',
                recommendation='Fix it.',
                references='L1',
                first_seen_at=scan.created_at,
                last_seen_at=scan.created_at,
                occurrence_count=1,
            ),
            Finding(
                scan_id=scan.id,
                website_id=website_id,
                title='High issue',
                slug='high-issue',
                fingerprint=f'{website_id}:H1:headers',
                severity='high',
                priority='high',
                category='security_headers',
                status='acknowledged',
                description='High issue',
                evidence='[]',
                recommendation='Fix it.',
                references='H1',
                first_seen_at=scan.created_at,
                last_seen_at=scan.created_at,
                occurrence_count=1,
            ),
        ]
        db.add_all(entries)
        db.commit()

        overview = RiskService(db).overview_for_user(owner_id)
        assert overview['risk_model_version'] == '1.0'
        assert overview['score'] == 9
        assert 0 <= overview['score'] <= 100
        assert overview['severity_counts']['high'] == 1
        assert overview['severity_counts']['low'] == 1
        assert overview['top_risk_drivers']
    finally:
        db.close()
