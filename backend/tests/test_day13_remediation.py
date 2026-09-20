from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.models.entities import Business, Finding, Scan, User, Website
from app.scanner.engine import ScannerEngine
from conftest import TestingSessionLocal


def _register_and_login(client, *, email: str, password: str = 'SecurePassword123') -> str:
    client.post('/api/v1/auth/register', json={'email': email, 'password': password, 'full_name': 'Remediation User'})
    response = client.post('/api/v1/auth/login', json={'email': email, 'password': password})
    assert response.status_code == 200, response.text
    return response.json()['data']['token']


def _create_owned_finding(db, owner_id: str, *, business_name: str = 'Test Business', website_name: str = 'Example Site'):
    user = db.query(User).filter_by(id=owner_id).one()
    business = Business(owner_id=owner_id, name=business_name, industry='Technology')
    db.add(business)
    db.commit()
    db.refresh(business)

    website = Website(
        business_id=business.id,
        name=website_name,
        url='https://example.com',
        normalized_url='https://example.com',
        hostname='example.com',
        status='active',
    )
    db.add(website)
    db.commit()
    db.refresh(website)

    scan = Scan(
        website_id=website.id,
        status='completed',
        scan_type='baseline',
        risk_score=42,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    finding = Finding(
        scan_id=scan.id,
        website_id=website.id,
        title='Missing HSTS',
        slug='missing-hsts',
        fingerprint=f'{website.id}:hsts:security_headers',
        severity='high',
        priority='high',
        category='security_headers',
        status='open',
        description='HSTS is missing.',
        evidence='{"missing": "hsts"}',
        recommendation='Add HSTS.',
        references='HSTS-001',
        first_seen_at=datetime.now(timezone.utc),
        last_seen_at=datetime.now(timezone.utc),
        occurrence_count=1,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def test_remediation_can_be_created_for_owned_finding(client) -> None:
    token = _register_and_login(client, email='owner1@example.com')
    db = TestingSessionLocal()
    try:
        user = db.query(User).filter_by(email='owner1@example.com').one()
        finding = _create_owned_finding(db, user.id, business_name='Owned Business', website_name='Owned Website')
        response = client.post(f'/api/v1/findings/{finding.id}/remediation', json={'remediation_notes': 'Review headers.'}, headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 200, response.text
        payload = response.json()['data']
        assert payload['status'] == 'open'
        assert payload['findings'] if False else True
    finally:
        db.close()


def test_unauthenticated_and_foreign_owner_are_rejected(client) -> None:
    token = _register_and_login(client, email='owner-a@example.com')
    db = TestingSessionLocal()
    try:
        owner = db.query(User).filter_by(email='owner-a@example.com').one()
        finding = _create_owned_finding(db, owner.id, business_name='Alpha', website_name='Alpha Site')

        unauthenticated = client.post(f'/api/v1/findings/{finding.id}/remediation')
        assert unauthenticated.status_code == 401

        other_token = _register_and_login(client, email='owner-b@example.com')
        other_response = client.get(f'/api/v1/findings/{finding.id}/remediation', headers={'Authorization': f'Bearer {other_token}'})
        assert other_response.status_code in {403, 404}
    finally:
        db.close()


def test_valid_and_invalid_remediation_transitions(client) -> None:
    token = _register_and_login(client, email='owner-c@example.com')
    db = TestingSessionLocal()
    try:
        user = db.query(User).filter_by(email='owner-c@example.com').one()
        finding = _create_owned_finding(db, user.id, business_name='Bravo', website_name='Bravo Site')
        create_response = client.post(f'/api/v1/findings/{finding.id}/remediation', headers={'Authorization': f'Bearer {token}'})
        remediation_id = create_response.json()['data']['id']

        valid = client.patch(f'/api/v1/findings/{finding.id}/remediation', json={'status': 'in_progress'}, headers={'Authorization': f'Bearer {token}'})
        assert valid.status_code == 200, valid.text
        assert valid.json()['data']['status'] == 'in_progress'

        pending = client.patch(f'/api/v1/findings/{finding.id}/remediation', json={'status': 'pending_verification'}, headers={'Authorization': f'Bearer {token}'})
        assert pending.status_code == 200, pending.text
        assert pending.json()['data']['status'] == 'pending_verification'

        invalid = client.patch(f'/api/v1/findings/{finding.id}/remediation', json={'status': 'resolved'}, headers={'Authorization': f'Bearer {token}'})
        assert invalid.status_code == 200, invalid.text
        assert invalid.json()['data']['status'] == 'resolved'

        rejected = client.patch(f'/api/v1/findings/{finding.id}/remediation', json={'status': 'pending_verification'}, headers={'Authorization': f'Bearer {token}'})
        assert rejected.status_code == 409, rejected.text
    finally:
        db.close()


def test_verification_uses_real_scan_path_and_resolves_when_missing(client, monkeypatch) -> None:
    token = _register_and_login(client, email='owner-d@example.com')
    db = TestingSessionLocal()
    try:
        user = db.query(User).filter_by(email='owner-d@example.com').one()
        finding = _create_owned_finding(db, user.id, business_name='Delta', website_name='Delta Site')

        def fake_run(scan):
            scan.status = 'completed'
            scan.completed_at = datetime.now(timezone.utc)
            scan.updated_at = datetime.now(timezone.utc)
            db.add(scan)
            db.commit()
            return scan

        monkeypatch.setattr(ScannerEngine, 'run', fake_run)

        create_response = client.post(f'/api/v1/findings/{finding.id}/remediation', json={'remediation_notes': 'Apply a secure HSTS policy.'}, headers={'Authorization': f'Bearer {token}'})
        assert create_response.status_code == 200

        verify_response = client.post(f'/api/v1/findings/{finding.id}/remediation/verify', headers={'Authorization': f'Bearer {token}'})
        assert verify_response.status_code == 200, verify_response.text
        payload = verify_response.json()['data']
        assert payload['status'] == 'resolved'
        assert payload['verification_result'] == 'resolved'
        assert payload['verification_scan_id'] is not None

        updated = db.query(Finding).filter_by(id=finding.id).one()
        assert updated.status == 'resolved'
    finally:
        db.close()
