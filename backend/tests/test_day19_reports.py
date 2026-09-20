from __future__ import annotations

from pathlib import Path

from app.models.entities import Finding
from conftest import TestingSessionLocal
from test_day9_reports import _create_report_fixture, _register_and_login


def test_day19_unauthenticated_and_cross_business_report_access_are_rejected(client) -> None:
    owner_token, owner_id = _register_and_login(client, email='day19-owner@example.com')
    other_token, _ = _register_and_login(client, email='day19-other@example.com')
    db = TestingSessionLocal()
    try:
        business, website, scan, _ = _create_report_fixture(db, owner_id)
        created = client.post(
            '/api/v1/reports',
            json={'business_id': business.id, 'website_id': website.id, 'scan_id': scan.id},
            headers={'Authorization': f'Bearer {owner_token}'},
        )
        assert created.status_code == 201, created.text
        report_id = created.json()['data']['id']
        assert client.get(f'/api/v1/reports/{report_id}').status_code in {401, 403}
        assert client.get(f'/api/v1/reports/{report_id}', headers={'Authorization': f'Bearer {other_token}'}).status_code in {403, 404}
        assert client.get(f'/api/v1/reports/{report_id}/download', headers={'Authorization': f'Bearer {other_token}'}).status_code in {403, 404}
    finally:
        db.close()


def test_day19_zero_findings_report_is_a_valid_pdf(client) -> None:
    token, owner_id = _register_and_login(client, email='day19-empty@example.com')
    db = TestingSessionLocal()
    try:
        business, website, scan, finding = _create_report_fixture(db, owner_id)
        db.delete(finding)
        db.commit()
        response = client.post(
            '/api/v1/reports',
            json={'business_id': business.id, 'website_id': website.id, 'scan_id': scan.id},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert response.status_code == 201, response.text
        report_id = response.json()['data']['id']
        download = client.get(f'/api/v1/reports/{report_id}/download', headers={'Authorization': f'Bearer {token}'})
        assert download.status_code == 200
        assert download.headers['content-type'].startswith('application/pdf')
        assert download.content.startswith(b'%PDF-')
        assert len(download.content) > 500
    finally:
        db.close()


def test_day19_long_multiple_findings_and_sensitive_data_are_handled(client) -> None:
    token, owner_id = _register_and_login(client, email='day19-long@example.com')
    db = TestingSessionLocal()
    try:
        business, website, scan, finding = _create_report_fixture(db, owner_id)
        finding.description = 'Long description <unsafe> ' * 400
        finding.evidence = 'api_key=synthetic-day19-secret credentials=credential-value-day19 ' * 30
        for index in range(15):
            db.add(Finding(
                scan_id=scan.id,
                website_id=website.id,
                title=f'Finding {index}',
                slug=f'finding-{index}',
                fingerprint=f'fingerprint-{index}',
                severity='low',
                category='test',
                status='open',
                description='Additional finding content.',
                evidence='No sensitive evidence.',
                recommendation='Apply the documented remediation.',
            ))
        db.commit()
        response = client.post(
            '/api/v1/reports',
            json={'business_id': business.id, 'website_id': website.id, 'scan_id': scan.id, 'title': 'Long <report> & safe'},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert response.status_code == 201, response.text
        metadata = response.json()['data']['metadata']
        assert len(metadata['findings']) == 16
        assert 'synthetic-day19-secret' not in str(metadata)
        assert 'credential-value-day19' not in str(metadata)
        report_id = response.json()['data']['id']
        report_file = Path(__file__).resolve().parents[2] / 'reports' / 'generated' / f'{report_id}.pdf'
        assert report_file.read_bytes().startswith(b'%PDF-')
    finally:
        db.close()


def test_day19_scan_must_match_selected_website(client) -> None:
    token, owner_id = _register_and_login(client, email='day19-scope@example.com')
    db = TestingSessionLocal()
    try:
        business, website, scan, _ = _create_report_fixture(db, owner_id)
        from app.models.entities import Scan, Website

        second_website = Website(
            business_id=business.id,
            name='Second website',
            url='https://second.example.com',
            normalized_url='https://second.example.com',
            hostname='second.example.com',
            status='active',
        )
        db.add(second_website)
        db.flush()
        second_scan = Scan(website_id=second_website.id, status='completed', scan_type='baseline')
        db.add(second_scan)
        db.commit()
        response = client.post(
            '/api/v1/reports',
            json={'business_id': business.id, 'website_id': website.id, 'scan_id': second_scan.id},
            headers={'Authorization': f'Bearer {token}'},
        )
        assert response.status_code == 422
    finally:
        db.close()
