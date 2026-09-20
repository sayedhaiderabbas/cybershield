from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from app.models.entities import Business, Finding, Scan, Website
from app.services.report_service import ReportService
from conftest import TestingSessionLocal


def _register_and_login(client, *, email: str, password: str = 'SecurePassword123') -> tuple[str, str]:
    response = client.post('/api/v1/auth/register', json={'email': email, 'password': password, 'full_name': 'Owner User'})
    assert response.status_code == 201, response.text
    login = client.post('/api/v1/auth/login', json={'email': email, 'password': password})
    assert login.status_code == 200, login.text
    token = login.json()['data']['token']
    user_id = login.json()['data']['user']['id']
    return token, user_id


def _create_report_fixture(db, owner_id: str, *, business_name: str = 'Northlane Labs', website_name: str = 'Northlane website', website_url: str = 'https://example.com') -> tuple[Business, Website, Scan, Finding]:
    business = Business(owner_id=owner_id, name=business_name, industry='Technology')
    db.add(business)
    db.flush()

    website = Website(
        business_id=business.id,
        name=website_name,
        url=website_url,
        normalized_url=website_url,
        hostname='example.com',
        status='active',
    )
    db.add(website)
    db.flush()

    scan = Scan(website_id=website.id, status='completed', scan_type='baseline', risk_score=68)
    db.add(scan)
    db.flush()

    finding = Finding(
        scan_id=scan.id,
        website_id=website.id,
        title='Missing HSTS header',
        slug='missing-hsts-header',
        fingerprint='example.com:security_headers:missing-hsts',
        severity='medium',
        category='security_headers',
        status='open',
        description='The HTTPS response does not include the Strict-Transport-Security header.',
        evidence='Strict-Transport-Security: missing\nheader=absent',
        recommendation='Add a Strict-Transport-Security policy with a max-age and includeSubDomains when appropriate.',
        references='CS-HSTS-001',
    )
    db.add(finding)
    db.commit()
    db.refresh(business)
    db.refresh(website)
    db.refresh(scan)
    db.refresh(finding)
    return business, website, scan, finding


def test_report_creation_listing_and_detail_are_secure_and_real(client) -> None:
    token, owner_id = _register_and_login(client, email='report-owner@example.com')
    db = TestingSessionLocal()
    try:
        business, website, scan, finding = _create_report_fixture(db, owner_id)
        response = client.post(
            '/api/v1/reports',
            json={
                'business_id': business.id,
                'website_id': website.id,
                'scan_id': scan.id,
                'title': 'Quarterly security assessment',
                'report_type': 'security_assessment',
            },
            headers={'Authorization': f'Bearer {token}'},
        )
        assert response.status_code == 201, response.text
        payload = response.json()['data']
        assert payload['title'] == 'Quarterly security assessment'
        assert payload['business_id'] == business.id
        assert payload['website_id'] == website.id
        assert payload['status'] == 'completed'
        assert payload['risk_score_snapshot'] == 4
        assert payload['risk_model_version']
        assert payload['metadata']['risk_score'] == 4
        assert any(item['title'] == 'Missing HSTS header' for item in payload['metadata']['findings'])

        list_response = client.get('/api/v1/reports', headers={'Authorization': f'Bearer {token}'})
        assert list_response.status_code == 200, list_response.text
        assert list_response.json()['meta']['total'] >= 1

        detail_response = client.get(f"/api/v1/reports/{payload['id']}", headers={'Authorization': f'Bearer {token}'})
        assert detail_response.status_code == 200, detail_response.text
        detail = detail_response.json()['data']
        assert detail['status'] == 'completed'
        assert detail['report_type'] == 'security_assessment'
        assert detail['metadata']['findings'][0]['title'] == finding.title
        assert detail['metadata']['findings'][0]['severity'] == finding.severity
    finally:
        db.close()


def test_report_authorization_and_download_are_enforced(client) -> None:
    owner_token, owner_id = _register_and_login(client, email='owner-1@example.com')
    other_token, _ = _register_and_login(client, email='owner-2@example.com')
    db = TestingSessionLocal()
    try:
        business, website, scan, _ = _create_report_fixture(db, owner_id)
        report_response = client.post(
            '/api/v1/reports',
            json={'business_id': business.id, 'website_id': website.id, 'scan_id': scan.id},
            headers={'Authorization': f'Bearer {owner_token}'},
        )
        assert report_response.status_code == 201, report_response.text
        report_id = report_response.json()['data']['id']

        unauthorized = client.get(f'/api/v1/reports/{report_id}', headers={'Authorization': f'Bearer {other_token}'})
        assert unauthorized.status_code in {403, 404}, unauthorized.text

        missing = client.get('/api/v1/reports/does-not-exist', headers={'Authorization': f'Bearer {owner_token}'})
        assert missing.status_code == 404, missing.text

        download = client.get(f'/api/v1/reports/{report_id}/download', headers={'Authorization': f'Bearer {other_token}'})
        assert download.status_code in {403, 404}, download.text

        valid_download = client.get(f'/api/v1/reports/{report_id}/download', headers={'Authorization': f'Bearer {owner_token}'})
        assert valid_download.status_code == 200, valid_download.text
        assert valid_download.headers.get('content-type', '').startswith('application/pdf')
        assert 'filename=' in valid_download.headers.get('content-disposition', '').lower()
    finally:
        db.close()


def test_report_snapshot_and_pdf_are_generated_from_verified_data(client) -> None:
    token, owner_id = _register_and_login(client, email='snapshot-owner@example.com')
    db = TestingSessionLocal()
    try:
        business, website, scan, finding = _create_report_fixture(db, owner_id)
        response = client.post(
            '/api/v1/reports',
            json={'business_id': business.id, 'website_id': website.id, 'scan_id': scan.id, 'title': 'Snapshot verification report'},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert response.status_code == 201, response.text
        report_id = response.json()['data']['id']
        detail = client.get(f'/api/v1/reports/{report_id}', headers={'Authorization': f'Bearer {token}'})
        assert detail.status_code == 200, detail.text

        metadata = detail.json()['data']['metadata']
        assert metadata['risk_score'] == 4
        assert metadata['risk_model_version']
        assert metadata['scan']['id'] == scan.id
        assert metadata['business']['id'] == business.id
        assert metadata['findings'][0]['title'] == finding.title
        assert metadata['findings'][0]['severity'] == finding.severity
        assert metadata['findings'][0]['status'] == finding.status
        assert 'Strict-Transport-Security' in ' '.join(metadata['findings'][0]['evidence'])

        report_file = Path(__file__).resolve().parents[2] / 'reports' / 'generated' / f'{report_id}.pdf'
        assert report_file.exists(), 'PDF was not created in the controlled storage directory.'
        assert report_file.stat().st_size > 0
        pdf_bytes = report_file.read_bytes()
        assert b'%PDF-' in pdf_bytes
        assert b'CyberShield' in pdf_bytes
    finally:
        db.close()


def test_report_generation_failure_is_safely_handled(client) -> None:
    token, owner_id = _register_and_login(client, email='report-failure@example.com')
    db = TestingSessionLocal()
    try:
        business, website, scan, _ = _create_report_fixture(db, owner_id)
        with patch('app.services.report_service.ReportService._write_pdf', side_effect=RuntimeError('boom')):
            response = client.post(
                '/api/v1/reports',
                json={'business_id': business.id, 'website_id': website.id, 'scan_id': scan.id, 'title': 'Failure case'},
                headers={'Authorization': f'Bearer {token}'},
            )
            assert response.status_code == 500, response.text
            assert 'The report could not be generated.' in response.json()['detail']
    finally:
        db.close()


def test_report_download_block_traversal_attempts() -> None:
    storage_root = Path(__file__).resolve().parents[2] / 'reports' / 'generated'
    storage_root.mkdir(parents=True, exist_ok=True)
    traversal_file = Path(__file__).resolve().parents[2] / 'secret.txt'
    traversal_file.write_text('sensitive', encoding='utf-8')

    report = type('FakeReport', (), {'id': 'trav-1', 'artifact_path': '../../secret.txt'})()
    resolved = ReportService.resolve_download_path(report)
    assert resolved is None
    if traversal_file.exists():
        traversal_file.unlink()

