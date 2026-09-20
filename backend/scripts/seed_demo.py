from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid5
from urllib.parse import unquote, urlparse

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from app.core.security import hash_password
from app.db.session import SessionLocal, init_db
from app.models.entities import Alert, Business, Finding, MonitoringTarget, Report, Scan, User, Website
from app.services.audit_service import AuditEventService
from app.services.report_service import ReportService
from app.schemas import ReportCreate

DEMO_NAMESPACE = UUID('2f0a5bc7-e4ce-5bc5-a3a4-3be8b5c1d027')
DEMO_EMAIL = os.getenv('DEMO_EMAIL', 'demo@example.invalid').strip().lower()
DEMO_PASSWORD = os.getenv('DEMO_PASSWORD', '')


def demo_id(label: str) -> str:
    return str(uuid5(DEMO_NAMESPACE, label))


def require_demo_password() -> None:
    if len(DEMO_PASSWORD) < 12:
        raise SystemExit('DEMO_PASSWORD must be supplied and contain at least 12 characters.')


def ensure_sqlite_parent() -> None:
    database_url = os.getenv('DATABASE_URL', '')
    parsed = urlparse(database_url)
    if parsed.scheme != 'sqlite' or parsed.path in {'', ':memory:'}:
        return
    raw_path = unquote(parsed.path)
    if len(raw_path) >= 3 and raw_path[0] == '/' and raw_path[2] == ':':
        raw_path = raw_path[1:]
    database_path = Path(raw_path)
    if database_path.name:
        database_path.parent.mkdir(parents=True, exist_ok=True)


def get_or_create(session, model, identity: str, **values):
    entity = session.get(model, demo_id(identity))
    if entity is None:
        entity = model(id=demo_id(identity), **values)
        session.add(entity)
        session.flush()
    return entity


def seed_demo() -> dict[str, str]:
    require_demo_password()
    ensure_sqlite_parent()
    init_db()
    session = SessionLocal()
    now = datetime.now(timezone.utc)
    try:
        user = get_or_create(
            session,
            User,
            'user',
            email=DEMO_EMAIL,
            password_hash=hash_password(DEMO_PASSWORD),
            full_name='CyberShield Demo Operator',
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        user.email = DEMO_EMAIL
        user.password_hash = hash_password(DEMO_PASSWORD)
        user.full_name = 'CyberShield Demo Operator'
        user.is_active = True

        business = get_or_create(
            session,
            Business,
            'business',
            owner_id=user.id,
            name='Northstar Demo Studio',
            industry='Professional services',
            description='Synthetic CyberShield hackathon demonstration business.',
            created_at=now,
            updated_at=now,
        )
        website = get_or_create(
            session,
            Website,
            'website',
            business_id=business.id,
            name='Northstar public website',
            url='https://demo.cybershield.local',
            normalized_url='https://demo.cybershield.local/',
            hostname='demo.cybershield.local',
            status='watch',
            created_at=now,
            updated_at=now,
            last_scan_at=now - timedelta(hours=2),
        )

        previous_scan = get_or_create(
            session,
            Scan,
            'scan-previous',
            website_id=website.id,
            status='completed',
            scan_type='baseline',
            risk_score=54,
            started_at=now - timedelta(days=2, hours=2),
            completed_at=now - timedelta(days=2, hours=1, minutes=59),
            created_at=now - timedelta(days=2, hours=2),
            updated_at=now - timedelta(days=2, hours=1, minutes=59),
        )
        current_scan = get_or_create(
            session,
            Scan,
            'scan-current',
            website_id=website.id,
            status='completed',
            scan_type='baseline',
            risk_score=68,
            started_at=now - timedelta(hours=2),
            completed_at=now - timedelta(hours=1, minutes=59),
            created_at=now - timedelta(hours=2),
            updated_at=now - timedelta(hours=1, minutes=59),
        )

        finding_values = [
            (
                'finding-missing-headers',
                'Missing security headers',
                'missing-security-headers',
                'high',
                'headers',
                'Several recommended browser security headers are not present.',
                'The response did not include a complete security-header baseline.',
                'Configure the missing headers at the web server or reverse proxy.',
            ),
            (
                'finding-https',
                'HTTPS configuration needs review',
                'https-configuration-review',
                'medium',
                'transport',
                'The demo website requires an HTTPS configuration review.',
                'The transport check identified a configuration that deserves review.',
                'Review TLS configuration and enforce HTTPS redirects.',
            ),
            (
                'finding-cookie-flags',
                'Cookie security flags need review',
                'cookie-security-flags',
                'low',
                'cookies',
                'A cookie configuration should be reviewed for secure browser flags.',
                'The cookie check found a flag configuration requiring review.',
                'Set Secure, HttpOnly, and SameSite attributes where applicable.',
            ),
        ]
        for identity, title, slug, severity, category, description, evidence, recommendation in finding_values:
            finding = get_or_create(
                session,
                Finding,
                identity,
                scan_id=current_scan.id,
                website_id=website.id,
                title=title,
                slug=slug,
                fingerprint=f'demo:{slug}',
                severity=severity,
                priority='high' if severity == 'high' else 'normal',
                category=category,
                status='open',
                description=description,
                evidence=evidence,
                recommendation=recommendation,
                references='https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers',
                first_seen_at=now - timedelta(days=2),
                last_seen_at=now - timedelta(hours=1, minutes=59),
                occurrence_count=1,
                created_at=now - timedelta(days=2),
                updated_at=now - timedelta(hours=1, minutes=59),
            )
            finding.scan_id = current_scan.id
            finding.website_id = website.id

        monitoring = get_or_create(
            session,
            MonitoringTarget,
            'monitoring',
            business_id=business.id,
            website_id=website.id,
            enabled=True,
            schedule='daily',
            interval_minutes=1440,
            last_check_at=now - timedelta(hours=1),
            next_check_at=now + timedelta(hours=23),
            last_scan_id=current_scan.id,
            previous_scan_id=previous_scan.id,
            failure_count=0,
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(hours=1),
        )

        alert = get_or_create(
            session,
            Alert,
            'alert-missing-headers',
            business_id=business.id,
            website_id=website.id,
            monitoring_id=monitoring.id,
            scan_id=current_scan.id,
            finding_id=demo_id('finding-missing-headers'),
            alert_type='NEW_FINDING',
            severity='high',
            title='New high-severity finding requires review',
            message='The demo monitoring check identified a high-severity header finding.',
            status='open',
            deduplication_key='demo:new-finding:missing-security-headers',
            created_at=now - timedelta(hours=1),
            updated_at=now - timedelta(hours=1),
        )
        alert.status = 'open'

        session.commit()
        session.refresh(business)
        existing_report = session.query(Report).filter_by(
            business_id=business.id,
            title='Northstar Demo Studio Security Assessment',
        ).first()
        if existing_report is None:
            ReportService(session).create(
                user.id,
                ReportCreate(
                    business_id=business.id,
                    website_id=website.id,
                    scan_id=current_scan.id,
                    title='Northstar Demo Studio Security Assessment',
                    report_type='security_assessment',
                ),
            )
        AuditEventService(session).record_event(
            event_type='BUSINESS',
            action='DEMO_DATA_READY',
            message='Synthetic demonstration data is ready.',
            actor_user_id=user.id,
            business_id=business.id,
            resource_type='demo',
            resource_id=business.id,
            outcome='SUCCESS',
            severity='info',
            request_id=demo_id('seed'),
        )
        session.commit()
        return {'email': user.email, 'business_id': business.id, 'website_id': website.id, 'monitoring_id': monitoring.id}
    finally:
        session.close()


if __name__ == '__main__':
    print(seed_demo())
