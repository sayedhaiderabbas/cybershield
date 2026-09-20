from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from app.models.entities import Alert, Business, Finding, MonitoringTarget, Scan, User, Website
from app.services.alert_service import AlertService
from conftest import TestingSessionLocal


def _register_and_login(client, *, email: str, password: str = 'SecurePassword123') -> str:
    client.post('/api/v1/auth/register', json={'email': email, 'password': password, 'full_name': 'Alert Test User'})
    response = client.post('/api/v1/auth/login', json={'email': email, 'password': password})
    assert response.status_code == 200, response.text
    return response.json()['data']['token']


def _make_owner(db: TestingSessionLocal):
    user = User(email=f'alert-owner-{uuid.uuid4()}@example.com', password_hash='hash', full_name='Alert Owner', is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)

    business = Business(owner_id=user.id, name='Alert Business', industry='Technology')
    db.add(business)
    db.commit()
    db.refresh(business)

    website = Website(
        business_id=business.id,
        name='Alert Site',
        url='https://example.com',
        normalized_url='https://example.com',
        hostname='example.com',
        status='active',
    )
    db.add(website)
    db.commit()
    db.refresh(website)

    target = MonitoringTarget(
        business_id=business.id,
        website_id=website.id,
        enabled=True,
        schedule='daily',
        interval_minutes=1440,
        next_check_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return user, business, website, target


def test_new_critical_finding_creates_critical_alert() -> None:
    db = TestingSessionLocal()
    try:
        _, _, website, target = _make_owner(db)
        previous_scan = Scan(website_id=website.id, status='completed', scan_type='monitoring', risk_score=10, created_at=datetime.now(timezone.utc))
        current_scan = Scan(website_id=website.id, status='completed', scan_type='monitoring', risk_score=40, created_at=datetime.now(timezone.utc))
        db.add_all([previous_scan, current_scan])
        db.commit()
        db.refresh(previous_scan)
        db.refresh(current_scan)
        critical_finding = Finding(
            scan_id=current_scan.id,
            website_id=website.id,
            title='Missing strict transport security',
            slug='missing-hsts',
            fingerprint=f'{website.id}:hsts:security_headers',
            severity='critical',
            category='security_headers',
            status='open',
            description='The site is missing HSTS.',
            evidence='{"missing":"hsts"}',
            recommendation='Add HSTS.',
            references='HSTS-001',
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
            occurrence_count=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(critical_finding)
        db.commit()
        db.refresh(critical_finding)

        alerts = AlertService(db).evaluate_monitoring_result(target.id, current_scan, previous_scan)
        assert any(alert.alert_type == 'NEW_CRITICAL_FINDING' and alert.severity == 'critical' for alert in alerts)
        assert db.query(Alert).filter_by(alert_type='NEW_CRITICAL_FINDING').count() == 1
    finally:
        db.close()


def test_monitoring_failure_creates_safe_alert() -> None:
    db = TestingSessionLocal()
    try:
        _, _, website, _ = _make_owner(db)
        scan = Scan(website_id=website.id, status='failed', scan_type='monitoring', risk_score=0, error_code='SCAN_FAILED', created_at=datetime.now(timezone.utc))
        db.add(scan)
        db.commit()
        db.refresh(scan)

        alert = AlertService(db).evaluate_monitoring_failure(scan)
        assert alert is not None
        assert alert.alert_type == 'MONITORING_FAILURE'
        assert 'stack trace' not in alert.message.lower()
        assert alert.severity == 'medium'
    finally:
        db.close()


def test_repeated_monitoring_failure_does_not_duplicate() -> None:
    db = TestingSessionLocal()
    try:
        _, _, website, _ = _make_owner(db)
        first_scan = Scan(website_id=website.id, status='failed', scan_type='monitoring', error_code='SCAN_FAILED', created_at=datetime.now(timezone.utc))
        second_scan = Scan(website_id=website.id, status='failed', scan_type='monitoring', error_code='SCAN_FAILED', created_at=datetime.now(timezone.utc) + timedelta(minutes=1))
        db.add_all([first_scan, second_scan])
        db.commit()
        db.refresh(first_scan)
        db.refresh(second_scan)

        first_alert = AlertService(db).evaluate_monitoring_failure(first_scan)
        second_alert = AlertService(db).evaluate_monitoring_failure(second_scan)

        assert first_alert is not None
        assert second_alert is not None
        assert first_alert.id == second_alert.id
        assert db.query(Alert).filter_by(alert_type='MONITORING_FAILURE').count() == 1
    finally:
        db.close()


def test_deduplication_and_lifecycle() -> None:
    db = TestingSessionLocal()
    try:
        owner, _, website, target = _make_owner(db)
        previous_scan = Scan(website_id=website.id, status='completed', scan_type='monitoring', risk_score=10, created_at=datetime.now(timezone.utc))
        current_scan = Scan(website_id=website.id, status='completed', scan_type='monitoring', risk_score=22, created_at=datetime.now(timezone.utc))
        db.add_all([previous_scan, current_scan])
        db.commit()
        db.refresh(previous_scan)
        db.refresh(current_scan)

        finding = Finding(
            scan_id=current_scan.id,
            website_id=website.id,
            title='TLS certificate warning',
            slug='tls-certificate-warning',
            fingerprint=f'{website.id}:tls:certificate',
            severity='high',
            category='tls',
            status='open',
            description='The certificate is expiring soon.',
            evidence='{"warning":"certificate"}',
            recommendation='Renew the certificate.',
            references='TLS-002',
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
            occurrence_count=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)

        first_pass = AlertService(db).evaluate_monitoring_result(target.id, current_scan, previous_scan)
        second_pass = AlertService(db).evaluate_monitoring_result(target.id, current_scan, previous_scan)
        assert len(first_pass) > 0
        assert db.query(Alert).filter(Alert.alert_type.in_({'NEW_HIGH_FINDING', 'SIGNIFICANT_SECURITY_CHANGE', 'RISK_SCORE_INCREASE'})).count() <= 3
        assert db.query(Alert).count() == len(first_pass) or db.query(Alert).count() == len(first_pass) + 1

        alert = db.query(Alert).order_by(Alert.created_at.desc()).first()
        assert alert is not None

        updated = AlertService(db).update_alert_status(alert.id, owner.id, {'status': 'acknowledged'})
        assert updated.status == 'acknowledged'

        resolved = AlertService(db).update_alert_status(alert.id, owner.id, {'status': 'resolved'})
        assert resolved.status == 'resolved'

        invalid = None
        try:
            AlertService(db).update_alert_status(alert.id, owner.id, {'status': 'open'})
        except Exception:
            invalid = True
        assert invalid is True
    finally:
        db.close()


def test_reappearance_can_create_new_alert() -> None:
    db = TestingSessionLocal()
    try:
        _, _, website, target = _make_owner(db)
        initial = Scan(website_id=website.id, status='completed', scan_type='monitoring', risk_score=15, created_at=datetime.now(timezone.utc))
        follow_up = Scan(website_id=website.id, status='completed', scan_type='monitoring', risk_score=20, created_at=datetime.now(timezone.utc) + timedelta(minutes=1))
        db.add_all([initial, follow_up])
        db.commit()
        db.refresh(initial)
        db.refresh(follow_up)

        finding = Finding(
            scan_id=follow_up.id,
            website_id=website.id,
            title='Insecure protocol support',
            slug='insecure-protocols',
            fingerprint=f'{website.id}:proto:tls',
            severity='high',
            category='tls',
            status='open',
            description='Protocols are insecure.',
            evidence='{"insecure":true}',
            recommendation='Disable legacy TLS.',
            references='TLS-010',
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
            occurrence_count=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(finding)
        db.commit()

        alerts = AlertService(db).evaluate_monitoring_result(target.id, follow_up, initial)
        assert any(alert.alert_type == 'NEW_HIGH_FINDING' for alert in alerts)
    finally:
        db.close()


def test_alert_summary_is_owner_scoped(client) -> None:
    owner_token = _register_and_login(client, email=f'summary-owner-{uuid.uuid4()}@example.com')
    other_token = _register_and_login(client, email=f'summary-other-{uuid.uuid4()}@example.com')

    owner_business = client.post(
        '/api/v1/businesses',
        json={'name': 'Summary Business'},
        headers={'Authorization': f'Bearer {owner_token}'},
    )
    assert owner_business.status_code == 201
    business_id = owner_business.json()['data']['id']
    website = client.post(
        '/api/v1/websites',
        json={'business_id': business_id, 'name': 'Summary Site', 'url': 'https://summary.example'},
        headers={'Authorization': f'Bearer {owner_token}'},
    )
    assert website.status_code == 201
    website_id = website.json()['data']['id']
    db = TestingSessionLocal()
    try:
        db.add(Alert(
            business_id=business_id,
            website_id=website_id,
            alert_type='MONITORING_FAILURE',
            severity='critical',
            title='Assessment failed',
            message='The assessment could not be completed.',
            status='open',
            deduplication_key=f'summary-{uuid.uuid4()}',
        ))
        db.commit()
    finally:
        db.close()

    response = client.get('/api/v1/alerts/summary', headers={'Authorization': f'Bearer {owner_token}'})
    assert response.status_code == 200
    assert response.json()['data']['open'] == 1
    assert response.json()['data']['by_severity']['critical'] == 1

    other_response = client.get('/api/v1/alerts/summary', headers={'Authorization': f'Bearer {other_token}'})
    assert other_response.status_code == 200
    assert other_response.json()['data']['total'] == 0
