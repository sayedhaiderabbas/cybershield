from __future__ import annotations

import threading
import re
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.entities import Business, Finding, MonitoringTarget, Scan, Website
from app.repositories.monitoring_repository import MonitoringRepository
from app.schemas import MonitoringTargetCreate, MonitoringTargetUpdate, ScanCreate
from app.services.base import ensure_entity
from app.services.scan_service import ScanService

_SCHEDULE_INTERVALS = {'daily': 1440, 'weekly': 10080}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_monitoring_text(value: object | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    patterns = [
        (r'(?i)(authorization\s*:\s*)bearer\s+[A-Za-z0-9._~+/=-]+', r'\1Bearer <redacted>'),
        (r'(?i)(cookie|password|credentials?|api[_-]?key|token|secret)\s*[:=]\s*([^\s,;]+)', r'\1=<redacted>'),
        (r'(?i)eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', '<redacted-jwt>'),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text[:500]


class MonitoringService:
    _scheduler_lock = threading.Lock()
    _running_targets: set[str] = set()

    def __init__(self, session: Session) -> None:
        self.session = session
        self.repo = MonitoringRepository(session)

    @staticmethod
    def normalize_schedule(schedule: str | None, interval_minutes: int | None) -> tuple[str, int]:
        if schedule:
            normalized = schedule.lower().strip()
            if normalized not in _SCHEDULE_INTERVALS:
                raise HTTPException(status_code=400, detail='Schedule must be one of: daily, weekly.')
            return normalized, _SCHEDULE_INTERVALS[normalized]
        if interval_minutes is not None:
            value = max(1, min(int(interval_minutes), 10080))
            if value >= 10080:
                return 'weekly', 10080
            return 'daily', max(1440, value)
        return 'daily', 1440

    def create(self, owner_id: str, payload: MonitoringTargetCreate) -> MonitoringTarget:
        business = self.session.query(Business).filter(Business.id == payload.business_id, Business.owner_id == owner_id).one_or_none()
        ensure_entity(business, 'Business not found or access denied.')
        website = self.session.query(Website).join(Website.business).filter(
            Website.id == payload.website_id,
            Website.business.has(id=payload.business_id),
            Website.business.has(owner_id=owner_id),
        ).one_or_none()
        ensure_entity(website, 'Website not found or access denied.')
        existing = self.session.query(MonitoringTarget).filter(
            MonitoringTarget.business_id == payload.business_id,
            MonitoringTarget.website_id == payload.website_id,
        ).one_or_none()
        if existing is not None:
            raise HTTPException(status_code=409, detail='Monitoring is already configured for this website.')

        schedule, interval_minutes = self.normalize_schedule(payload.schedule, payload.interval_minutes)
        now = utcnow()
        target = MonitoringTarget(
            business_id=payload.business_id,
            website_id=payload.website_id,
            enabled=bool(payload.enabled),
            schedule=schedule,
            interval_minutes=interval_minutes,
            last_check_at=None,
            next_check_at=now + timedelta(minutes=interval_minutes) if payload.enabled else None,
            paused_at=None if payload.enabled else now,
            failure_count=0,
            last_error=None,
            created_at=now,
            updated_at=now,
        )
        self.repo.add(target)
        self.repo.commit()
        self.repo.refresh(target)
        return target

    def list(self, owner_id: str, page: int, page_size: int) -> tuple[list[MonitoringTarget], int]:
        query = self.session.query(MonitoringTarget).join(Business).filter(Business.owner_id == owner_id)
        total = query.count()
        items = query.order_by(MonitoringTarget.created_at.desc(), MonitoringTarget.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
        return items, total

    def get(self, monitoring_id: str, owner_id: str) -> MonitoringTarget:
        target = self.session.query(MonitoringTarget).join(Business).filter(MonitoringTarget.id == monitoring_id, Business.owner_id == owner_id).one_or_none()
        ensure_entity(target, 'Monitoring target not found.')
        return target

    def overview(self, owner_id: str) -> list[dict[str, object]]:
        targets = self.session.query(MonitoringTarget).join(Business).filter(
            Business.owner_id == owner_id,
        ).order_by(MonitoringTarget.created_at.desc(), MonitoringTarget.id.desc()).all()
        overview: list[dict[str, object]] = []
        for target in targets:
            website = self.session.query(Website).filter(Website.id == target.website_id).one_or_none()
            scans = self.session.query(Scan).filter(
                Scan.website_id == target.website_id,
                Scan.status == 'completed',
            ).order_by(Scan.completed_at.desc(), Scan.created_at.desc()).limit(2).all()
            current_scan = scans[0] if scans else None
            previous_scan = scans[1] if len(scans) > 1 else None
            current_findings = len(current_scan.findings) if current_scan else 0
            open_findings = sum(
                1 for finding in current_scan.findings
                if str(finding.status).lower() in {'open', 'acknowledged'}
            ) if current_scan else 0
            risk_delta = None
            if current_scan and previous_scan and current_scan.risk_score is not None and previous_scan.risk_score is not None:
                risk_delta = current_scan.risk_score - previous_scan.risk_score
            overview.append({
                'monitoring_id': target.id,
                'business_id': target.business_id,
                'website_id': target.website_id,
                'website_name': website.name if website else 'Website',
                'website_url': website.url if website else None,
                'enabled': target.enabled,
                'status': 'failed' if target.last_error else ('active' if target.enabled else 'disabled'),
                'last_check_at': target.last_check_at,
                'last_scan_id': current_scan.id if current_scan else target.last_scan_id,
                'last_scan_at': current_scan.completed_at if current_scan else None,
                'current_risk_score': current_scan.risk_score if current_scan else None,
                'previous_risk_score': previous_scan.risk_score if previous_scan else None,
                'risk_delta': risk_delta,
                'findings_count': current_findings,
                'open_finding_count': open_findings,
                'failure_count': target.failure_count,
                'last_error': 'Monitoring check failed.' if target.last_error else None,
                'updated_at': target.updated_at,
            })
        return overview

    def update(self, monitoring_id: str, owner_id: str, payload: MonitoringTargetUpdate) -> MonitoringTarget:
        target = self.get(monitoring_id, owner_id)
        now = utcnow()
        if payload.enabled is not None:
            target.enabled = bool(payload.enabled)
            target.paused_at = None if target.enabled else now
            if target.enabled:
                target.next_check_at = now + timedelta(minutes=target.interval_minutes)
        if payload.schedule is not None:
            target.schedule, target.interval_minutes = self.normalize_schedule(payload.schedule, target.interval_minutes)
            if target.enabled:
                target.next_check_at = now + timedelta(minutes=target.interval_minutes)
        if payload.interval_minutes is not None:
            target.interval_minutes = max(1, min(int(payload.interval_minutes), 10080))
            target.schedule = 'weekly' if target.interval_minutes >= 10080 else 'daily'
            if target.enabled:
                target.next_check_at = now + timedelta(minutes=target.interval_minutes)
        target.updated_at = now
        self.repo.commit()
        return target

    def delete(self, monitoring_id: str, owner_id: str) -> None:
        target = self.get(monitoring_id, owner_id)
        self.session.delete(target)
        self.repo.commit()

    def get_due_targets(self) -> list[MonitoringTarget]:
        return self.session.query(MonitoringTarget).filter(
            MonitoringTarget.enabled.is_(True),
            MonitoringTarget.next_check_at.is_not(None),
            MonitoringTarget.next_check_at <= utcnow(),
        ).order_by(MonitoringTarget.next_check_at.asc()).all()

    def run_due_targets(self) -> list[str]:
        executed: list[str] = []
        for target in self.get_due_targets():
            result = self.execute_target(target.id)
            if result is not None:
                executed.append(result)
        return executed

    def execute_target(self, monitoring_id: str) -> str | None:
        with self._scheduler_lock:
            if monitoring_id in self._running_targets:
                return None
            self._running_targets.add(monitoring_id)

        try:
            target = self.session.query(MonitoringTarget).filter_by(id=monitoring_id).one_or_none()
            if target is None:
                return None
            if not target.enabled:
                return None
            now = utcnow()
            if target.next_check_at is not None and target.next_check_at > now:
                return None

            business_id = target.business_id
            website_owner_id = self.session.query(Business.owner_id).filter(Business.id == business_id).scalar_one_or_none()
            if website_owner_id is None:
                return None

            scan = ScanService(self.session).create(website_owner_id, ScanCreate(website_id=target.website_id, scan_type='monitoring'))
            target.previous_scan_id = target.last_scan_id
            target.last_scan_id = scan.id
            target.last_check_at = now
            target.last_error = None
            target.failure_count = 0
            target.next_check_at = now + timedelta(minutes=target.interval_minutes)
            target.updated_at = now
            self.repo.commit()
            return scan.id
        except Exception as exc:  # pragma: no cover - scheduler resilience
            target = self.session.query(MonitoringTarget).filter_by(id=monitoring_id).one_or_none()
            if target is not None:
                target.last_error = str(exc)[:255]
                target.failure_count = (target.failure_count or 0) + 1
                target.last_check_at = utcnow()
                target.next_check_at = utcnow() + timedelta(minutes=max(60, min(target.interval_minutes, 10080)))
                target.updated_at = utcnow()
                self.repo.commit()
            return None
        finally:
            with self._scheduler_lock:
                self._running_targets.discard(monitoring_id)

    def _history_summary(self, monitoring_id: str, owner_id: str) -> list[dict[str, object]]:
        target = self.get(monitoring_id, owner_id)
        scans = self.session.query(Scan).filter(Scan.website_id == target.website_id).order_by(
            Scan.completed_at.desc(),
            Scan.created_at.desc(),
            Scan.id.desc(),
        ).limit(2).all()
        summary: list[dict[str, object]] = []
        for index, scan in enumerate(scans):
            previous_scan = scans[index + 1] if index + 1 < len(scans) else None
            delta = self._summarize_scan_delta(scan, previous_scan)
            previous_score = previous_scan.risk_score if previous_scan and previous_scan.risk_score is not None else None
            current_score = scan.risk_score if scan.risk_score is not None else None
            risk_delta = None
            if previous_score is not None and current_score is not None:
                risk_delta = current_score - previous_score
            summary.append({
                'scan_id': scan.id,
                'status': scan.status,
                'started_at': scan.started_at,
                'completed_at': scan.completed_at,
                'findings_count': len(scan.findings),
                'new_findings_count': delta['new'],
                'resolved_findings_count': delta['resolved'],
                'changed_findings_count': delta['changed'],
                'persistent_findings_count': delta['persistent'],
                'previous_risk_score': previous_score,
                'current_risk_score': current_score,
                'risk_delta': risk_delta,
                'failure_code': scan.error_code,
            })
        return summary

    def get_history(self, monitoring_id: str, owner_id: str) -> list[dict[str, object]]:
        return self._history_summary(monitoring_id, owner_id)

    def get_history_page(
        self,
        monitoring_id: str,
        owner_id: str,
        page: int,
        page_size: int,
    ) -> tuple[list[dict[str, object]], int]:
        summary = self._history_summary(monitoring_id, owner_id)
        total = len(summary)
        start = (page - 1) * page_size
        return summary[start:start + page_size], total

    def get_changes(self, monitoring_id: str, owner_id: str) -> list[dict[str, object]]:
        target = self.get(monitoring_id, owner_id)
        scans = self.session.query(Scan).filter(Scan.website_id == target.website_id).order_by(
            Scan.completed_at.desc(),
            Scan.created_at.desc(),
        ).all()
        if len(scans) < 2:
            return []
        current_scan = scans[0]
        previous_scan = scans[1]
        previous_by_fingerprint = {finding.fingerprint: finding for finding in previous_scan.findings}
        current_by_fingerprint = {finding.fingerprint: finding for finding in current_scan.findings}
        changes: list[dict[str, object]] = []

        for fingerprint, finding in sorted(current_by_fingerprint.items()):
            if fingerprint not in previous_by_fingerprint:
                changes.append({
                    'fingerprint': fingerprint,
                    'title': _safe_monitoring_text(finding.title) or 'Finding',
                    'category': _safe_monitoring_text(finding.category) or 'unknown',
                    'severity': finding.severity,
                    'status': 'new',
                    'previous_severity': None,
                    'current_severity': finding.severity,
                    'previous_evidence': None,
                    'current_evidence': _safe_monitoring_text(finding.evidence),
                    'changed_at': current_scan.created_at,
                })
                continue
            previous_finding = previous_by_fingerprint[fingerprint]
            if self._is_meaningful_change(previous_finding, finding):
                changes.append({
                    'fingerprint': fingerprint,
                    'title': _safe_monitoring_text(finding.title) or 'Finding',
                    'category': _safe_monitoring_text(finding.category) or 'unknown',
                    'severity': finding.severity,
                    'status': 'changed',
                    'previous_severity': previous_finding.severity,
                    'current_severity': finding.severity,
                    'previous_evidence': _safe_monitoring_text(previous_finding.evidence),
                    'current_evidence': _safe_monitoring_text(finding.evidence),
                    'changed_at': current_scan.created_at,
                })
            else:
                changes.append({
                    'fingerprint': fingerprint,
                    'title': _safe_monitoring_text(finding.title) or 'Finding',
                    'category': _safe_monitoring_text(finding.category) or 'unknown',
                    'severity': finding.severity,
                    'status': 'persistent',
                    'previous_severity': previous_finding.severity,
                    'current_severity': finding.severity,
                    'previous_evidence': previous_finding.evidence,
                    'current_evidence': finding.evidence,
                    'changed_at': current_scan.created_at,
                })

        for fingerprint, finding in sorted(previous_by_fingerprint.items()):
            if fingerprint not in current_by_fingerprint:
                changes.append({
                    'fingerprint': fingerprint,
                    'title': finding.title,
                    'category': finding.category,
                    'severity': finding.severity,
                    'status': 'resolved',
                    'previous_severity': finding.severity,
                    'current_severity': None,
                    'previous_evidence': _safe_monitoring_text(finding.evidence),
                    'current_evidence': None,
                    'changed_at': current_scan.created_at,
                })

        return sorted(changes, key=lambda item: (str(item['status']), str(item['title'])))

    @staticmethod
    def _summarize_scan_delta(current_scan: Scan, previous_scan: Scan | None) -> dict[str, int]:
        if previous_scan is None:
            return {'new': len(current_scan.findings), 'resolved': 0, 'changed': 0, 'persistent': 0}

        previous_by_fingerprint = {finding.fingerprint: finding for finding in previous_scan.findings}
        current_by_fingerprint = {finding.fingerprint: finding for finding in current_scan.findings}
        new_count = len(set(current_by_fingerprint) - set(previous_by_fingerprint))
        resolved_count = len(set(previous_by_fingerprint) - set(current_by_fingerprint))
        changed_count = 0
        persistent_count = 0

        for fingerprint in set(current_by_fingerprint) & set(previous_by_fingerprint):
            previous_finding = previous_by_fingerprint[fingerprint]
            current_finding = current_by_fingerprint[fingerprint]
            if MonitoringService._is_meaningful_change(previous_finding, current_finding):
                changed_count += 1
            else:
                persistent_count += 1

        return {'new': new_count, 'resolved': resolved_count, 'changed': changed_count, 'persistent': persistent_count}

    @staticmethod
    def _is_meaningful_change(previous_finding: Finding, current_finding: Finding) -> bool:
        field_names = ['title', 'severity', 'category', 'description', 'recommendation', 'evidence']
        for field_name in field_names:
            previous_value = getattr(previous_finding, field_name, None)
            current_value = getattr(current_finding, field_name, None)
            if previous_value != current_value:
                return True
        return False


class MonitoringScheduler:
    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self, interval_seconds: int = 60) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, args=(interval_seconds,), daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _loop(self, interval_seconds: int) -> None:
        while not self._stop_event.is_set():
            try:
                db = SessionLocal()
                try:
                    MonitoringService(db).run_due_targets()
                finally:
                    db.close()
            except Exception:
                pass
            self._stop_event.wait(interval_seconds)


monitoring_scheduler = MonitoringScheduler()
