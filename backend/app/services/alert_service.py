from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.entities import Alert, Business, Finding, MonitoringTarget, Scan, Website

logger = logging.getLogger(__name__)

VALID_ALERT_TYPES = {
    'NEW_HIGH_FINDING',
    'NEW_CRITICAL_FINDING',
    'RISK_SCORE_INCREASE',
    'SIGNIFICANT_SECURITY_CHANGE',
    'MONITORING_FAILURE',
}
VALID_ALERT_STATUSES = {'open', 'acknowledged', 'resolved'}
VALID_SEVERITIES = {'info', 'low', 'medium', 'high', 'critical'}
RISK_INCREASE_THRESHOLD = 5


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_severity(value: str | None) -> str:
    mapping = {
        'info': 'info',
        'informational': 'info',
        'low': 'low',
        'medium': 'medium',
        'moderate': 'medium',
        'high': 'high',
        'critical': 'critical',
    }
    if value is None:
        return 'info'
    return mapping.get(str(value).strip().lower(), 'info')


class AlertService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def list(
        self,
        owner_id: str,
        page: int,
        page_size: int,
        status: str | None = None,
        severity: str | None = None,
        alert_type: str | None = None,
        website_id: str | None = None,
    ) -> tuple[list[Alert], int]:
        query = self.session.query(Alert).join(Business).filter(Business.owner_id == owner_id)
        if status is not None:
            query = query.filter(Alert.status == str(status).strip().lower())
        if severity is not None:
            query = query.filter(Alert.severity == normalize_severity(severity))
        if alert_type is not None:
            query = query.filter(Alert.alert_type == str(alert_type).strip().upper())
        if website_id is not None:
            website = self.session.query(Website).join(Website.business).filter(Website.id == website_id, Website.business.has(owner_id=owner_id)).one_or_none()
            if website is None:
                raise HTTPException(status_code=403, detail='Website access denied.')
            query = query.filter(Alert.website_id == website_id)
        query = query.order_by(Alert.created_at.desc(), Alert.id.desc())
        total = query.count()
        items = query.offset((page - 1) * page_size).limit(page_size).all()
        return items, total

    def get_alerts(self, owner_id: str, page: int, page_size: int, **kwargs: Any) -> tuple[list[Alert], int]:
        return self.list(owner_id, page, page_size, **kwargs)

    def get_alert(self, alert_id: str, owner_id: str) -> Alert:
        alert = self.session.query(Alert).join(Business).filter(Alert.id == alert_id, Business.owner_id == owner_id).one_or_none()
        if alert is None:
            raise HTTPException(status_code=404, detail='Alert not found.')
        return alert

    def get_unread_count(self, owner_id: str) -> int:
        return self.session.query(Alert).join(Business).filter(Business.owner_id == owner_id, Alert.status == 'open').count()

    def get_summary(self, owner_id: str) -> dict[str, Any]:
        alerts = self.session.query(Alert.severity, Alert.status, Alert.alert_type).join(Business).filter(Business.owner_id == owner_id).all()
        summary: dict[str, Any] = {
            'total': len(alerts),
            'open': 0,
            'acknowledged': 0,
            'resolved': 0,
            'by_severity': {severity: 0 for severity in sorted(VALID_SEVERITIES)},
            'open_by_severity': {severity: 0 for severity in sorted(VALID_SEVERITIES)},
            'open_monitoring_failures': 0,
        }
        for severity, status, alert_type in alerts:
            normalized_severity = normalize_severity(severity)
            normalized_status = str(status).lower()
            if normalized_status in {'open', 'acknowledged', 'resolved'}:
                summary[normalized_status] += 1
            summary['by_severity'][normalized_severity] = summary['by_severity'].get(normalized_severity, 0) + 1
            if normalized_status == 'open':
                summary['open_by_severity'][normalized_severity] = summary['open_by_severity'].get(normalized_severity, 0) + 1
                if alert_type == 'MONITORING_FAILURE':
                    summary['open_monitoring_failures'] += 1
        return summary

    def create_alert(
        self,
        *,
        business_id: str,
        website_id: str | None,
        alert_type: str,
        severity: str,
        title: str,
        message: str,
        monitoring_id: str | None = None,
        scan_id: str | None = None,
        finding_id: str | None = None,
        deduplication_key: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Alert | None:
        normalized_type = str(alert_type).strip().upper()
        if normalized_type not in VALID_ALERT_TYPES:
            raise ValueError(f'Unsupported alert type: {alert_type}')

        normalized_severity = normalize_severity(severity)
        if normalized_severity not in VALID_SEVERITIES:
            raise ValueError(f'Unsupported alert severity: {severity}')

        final_dedup_key = deduplication_key or self._build_deduplication_key(
            business_id=business_id,
            website_id=website_id,
            alert_type=normalized_type,
            monitoring_id=monitoring_id,
            scan_id=scan_id,
            finding_id=finding_id,
        )

        existing = self.session.query(Alert).filter(Alert.deduplication_key == final_dedup_key).one_or_none()
        if existing is not None:
            return existing

        now = utcnow()
        alert = Alert(
            business_id=business_id,
            website_id=website_id,
            monitoring_id=monitoring_id,
            scan_id=scan_id,
            finding_id=finding_id,
            alert_type=normalized_type,
            severity=normalized_severity,
            title=title,
            message=message,
            status='open',
            deduplication_key=final_dedup_key,
            alert_metadata=json.dumps(metadata, sort_keys=True) if metadata else None,
            created_at=now,
            updated_at=now,
        )
        self.session.add(alert)
        self.session.commit()
        self.session.refresh(alert)
        return alert

    def update_alert_status(self, alert_id: str, owner_id: str, status: str | dict[str, Any] | None) -> Alert:
        if isinstance(status, dict):
            payload = status
        else:
            payload = {'status': status}

        normalized_status = str(payload.get('status', '')).strip().lower()
        if normalized_status not in VALID_ALERT_STATUSES:
            raise HTTPException(status_code=422, detail='Unsupported alert status.')

        alert = self.get_alert(alert_id, owner_id)
        current_status = str(alert.status).strip().lower()
        allowed_next = {
            'open': {'acknowledged', 'resolved'},
            'acknowledged': {'resolved'},
            'resolved': set(),
        }
        if normalized_status not in allowed_next.get(current_status, set()):
            raise HTTPException(status_code=409, detail='Invalid alert lifecycle transition.')

        now = utcnow()
        alert.status = normalized_status
        if normalized_status == 'acknowledged' and alert.acknowledged_at is None:
            alert.acknowledged_at = now
        if normalized_status == 'resolved':
            alert.resolved_at = alert.resolved_at or now
        alert.updated_at = now
        self.session.commit()
        self.session.refresh(alert)
        return alert

    def evaluate_monitoring_result(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> list[Alert]:
        if args:
            if len(args) >= 3:
                monitoring_id, current_scan, previous_scan = args[:3]
                business_id = kwargs.get('business_id')
                website_id = kwargs.get('website_id')
            elif len(args) >= 2:
                current_scan, previous_scan = args[:2]
                monitoring_id = kwargs.get('monitoring_id')
                business_id = kwargs.get('business_id')
                website_id = kwargs.get('website_id')
            else:
                current_scan = args[0]
                previous_scan = kwargs.get('previous_scan')
                monitoring_id = kwargs.get('monitoring_id')
                business_id = kwargs.get('business_id')
                website_id = kwargs.get('website_id')
        else:
            monitoring_id = kwargs.get('monitoring_id')
            current_scan = kwargs.get('current_scan') or kwargs.get('scan')
            previous_scan = kwargs.get('previous_scan') or kwargs.get('baseline_scan')
            business_id = kwargs.get('business_id')
            website_id = kwargs.get('website_id')

        if current_scan is None:
            return []

        target = None
        if monitoring_id is not None:
            target = self.session.query(MonitoringTarget).filter_by(id=monitoring_id).one_or_none()
        if target is None and current_scan.website_id:
            target = self.session.query(MonitoringTarget).filter_by(website_id=current_scan.website_id).order_by(MonitoringTarget.created_at.desc()).first()
        if target is not None:
            business_id = business_id or target.business_id
            website_id = website_id or target.website_id
            monitoring_id = monitoring_id or target.id

        if business_id is None:
            website = self.session.query(Website).filter_by(id=current_scan.website_id).one_or_none()
            if website is not None:
                business_id = website.business_id
        if website_id is None:
            website_id = current_scan.website_id

        previous_by_fingerprint: dict[str, Finding] = {}
        current_by_fingerprint: dict[str, Finding] = {finding.fingerprint: finding for finding in current_scan.findings}
        if previous_scan is not None:
            previous_by_fingerprint = {finding.fingerprint: finding for finding in previous_scan.findings}

        new_fingerprints = sorted(set(current_by_fingerprint) - set(previous_by_fingerprint))
        changed_fingerprints: list[str] = []
        for fingerprint in set(current_by_fingerprint) & set(previous_by_fingerprint):
            previous_finding = previous_by_fingerprint[fingerprint]
            current_finding = current_by_fingerprint[fingerprint]
            if self._is_meaningful_change(previous_finding, current_finding):
                changed_fingerprints.append(fingerprint)

        created_alerts: list[Alert] = []
        for fingerprint in new_fingerprints:
            finding = current_by_fingerprint[fingerprint]
            if normalize_severity(finding.severity) == 'critical':
                alert = self.create_alert(
                    business_id=business_id,
                    website_id=website_id,
                    alert_type='NEW_CRITICAL_FINDING',
                    severity='critical',
                    title=finding.title,
                    message=f'New critical finding detected: {finding.title}.',
                    monitoring_id=monitoring_id,
                    scan_id=current_scan.id,
                    finding_id=finding.id,
                    deduplication_key=self._build_deduplication_key(business_id, website_id, 'NEW_CRITICAL_FINDING', monitoring_id, current_scan.id, finding.id),
                    metadata={'finding_id': finding.id, 'fingerprint': fingerprint, 'severity': 'critical'},
                )
                if alert is not None:
                    created_alerts.append(alert)
            elif normalize_severity(finding.severity) == 'high':
                alert = self.create_alert(
                    business_id=business_id,
                    website_id=website_id,
                    alert_type='NEW_HIGH_FINDING',
                    severity='high',
                    title=finding.title,
                    message=f'New high severity finding detected: {finding.title}.',
                    monitoring_id=monitoring_id,
                    scan_id=current_scan.id,
                    finding_id=finding.id,
                    deduplication_key=self._build_deduplication_key(business_id, website_id, 'NEW_HIGH_FINDING', monitoring_id, current_scan.id, finding.id),
                    metadata={'finding_id': finding.id, 'fingerprint': fingerprint, 'severity': 'high'},
                )
                if alert is not None:
                    created_alerts.append(alert)

        previous_score = 0.0 if previous_scan is None or previous_scan.risk_score is None else float(previous_scan.risk_score)
        current_score = 0.0 if current_scan.risk_score is None else float(current_scan.risk_score)
        risk_delta = current_score - previous_score
        if current_score > previous_score and risk_delta >= RISK_INCREASE_THRESHOLD:
            risk_alert = self.create_alert(
                business_id=business_id,
                website_id=website_id,
                alert_type='RISK_SCORE_INCREASE',
                severity='high' if risk_delta >= 15 else 'medium',
                title='Risk score increased',
                message=f'Current risk score increased from {previous_score} to {current_score}.',
                monitoring_id=monitoring_id,
                scan_id=current_scan.id,
                finding_id=None,
                deduplication_key=self._build_deduplication_key(business_id, website_id, 'RISK_SCORE_INCREASE', monitoring_id, current_scan.id, str(previous_score), str(current_score)),
                metadata={'previous_risk_score': previous_score, 'current_risk_score': current_score, 'risk_delta': risk_delta},
            )
            if risk_alert is not None:
                created_alerts.append(risk_alert)

        if new_fingerprints or changed_fingerprints:
            change_alert = self.create_alert(
                business_id=business_id,
                website_id=website_id,
                alert_type='SIGNIFICANT_SECURITY_CHANGE',
                severity='high' if any(normalize_severity(current_by_fingerprint[fingerprint].severity) in {'critical', 'high'} for fingerprint in new_fingerprints + changed_fingerprints) else 'medium',
                title='Meaningful security change detected',
                message='A meaningful security configuration change was detected during the latest assessment.',
                monitoring_id=monitoring_id,
                scan_id=current_scan.id,
                finding_id=None,
                deduplication_key=self._build_deduplication_key(business_id, website_id, 'SIGNIFICANT_SECURITY_CHANGE', monitoring_id, current_scan.id, ','.join(sorted(new_fingerprints + changed_fingerprints))),
                metadata={'new_fingerprint_count': len(new_fingerprints), 'changed_fingerprint_count': len(changed_fingerprints), 'risk_delta': risk_delta},
            )
            if change_alert is not None:
                created_alerts.append(change_alert)

        return created_alerts

    def evaluate_scan_result(self, scan: Scan) -> list[Alert]:
        if scan.scan_type != 'monitoring':
            return []
        if scan.status == 'failed' or scan.error_code:
            return [self.evaluate_monitoring_failure(scan)] if self.evaluate_monitoring_failure(scan) is not None else []

        target = self.session.query(MonitoringTarget).filter_by(website_id=scan.website_id).order_by(MonitoringTarget.created_at.desc()).first()
        if target is None:
            return []
        previous_scan = None
        if target.previous_scan_id:
            previous_scan = self.session.query(Scan).filter_by(id=target.previous_scan_id).one_or_none()
        elif target.last_scan_id and target.last_scan_id != scan.id:
            previous_scan = self.session.query(Scan).filter_by(id=target.last_scan_id).one_or_none()
        return self.evaluate_monitoring_result(monitoring_id=target.id, current_scan=scan, previous_scan=previous_scan, business_id=target.business_id, website_id=target.website_id)

    def evaluate_monitoring_failure(self, scan: Scan) -> Alert | None:
        if scan.scan_type != 'monitoring':
            return None
        target = self.session.query(MonitoringTarget).filter_by(website_id=scan.website_id).order_by(MonitoringTarget.created_at.desc()).first()
        if target is None:
            return None
        website = self.session.query(Website).filter_by(id=scan.website_id).one_or_none()
        business_id = target.business_id if target is not None else website.business_id if website is not None else None
        if business_id is None:
            return None
        reason = 'Target did not respond within the configured timeout.' if scan.error_code == 'SCAN_FAILED' else 'Scheduled security assessment could not be completed.'
        # A repeated scheduled failure is the same security event even when
        # the scheduler records it in a new scan row.
        return self.create_alert(
            business_id=business_id,
            website_id=scan.website_id,
            alert_type='MONITORING_FAILURE',
            severity='medium',
            title='Scheduled security assessment could not be completed.',
            message=reason,
            monitoring_id=target.id,
            scan_id=scan.id,
            deduplication_key=self._build_deduplication_key(
                business_id,
                scan.website_id,
                'MONITORING_FAILURE',
                target.id,
                scan.error_code or 'UNKNOWN_FAILURE',
            ),
            metadata={'monitoring_id': target.id, 'scan_id': scan.id, 'failure_code': scan.error_code},
        )

    @staticmethod
    def _build_deduplication_key(
        business_id: str | None,
        website_id: str | None,
        alert_type: str,
        monitoring_id: str | None = None,
        scan_id: str | None = None,
        *extra_parts: Any,
    ) -> str:
        parts = [str(value) for value in [business_id, website_id, alert_type, monitoring_id, scan_id, *extra_parts] if value is not None]
        return ':'.join(parts)

    @staticmethod
    def _is_meaningful_change(previous_finding: Finding, current_finding: Finding) -> bool:
        for field_name in ['title', 'severity', 'category', 'description', 'recommendation', 'evidence']:
            previous_value = getattr(previous_finding, field_name, None)
            current_value = getattr(current_finding, field_name, None)
            if previous_value != current_value:
                return True
        return False


def _fallback_alert_count(query: Any) -> int:
    return query.count() if hasattr(query, 'count') else 0
