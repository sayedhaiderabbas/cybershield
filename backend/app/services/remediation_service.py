from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.entities import Business, Finding, FindingRemediation, Scan, Website
from app.scanner.engine import ScannerEngine
from app.services.base import ensure_entity

VALID_REMEDIATION_STATUSES = {'open', 'in_progress', 'pending_verification', 'resolved'}
VALID_TRANSITIONS = {
    'open': {'in_progress'},
    'in_progress': {'open', 'pending_verification'},
    'pending_verification': {'open', 'in_progress', 'resolved'},
    'resolved': {'open'},
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FindingRemediationService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def _get_finding_for_owner(self, finding_id: str, owner_id: str) -> Finding:
        finding = (
            self.session.query(Finding)
            .join(Scan)
            .join(Website)
            .join(Business)
            .filter(Finding.id == finding_id, Business.owner_id == owner_id)
            .one_or_none()
        )
        ensure_entity(finding, 'Finding not found or access denied.')
        return finding

    def get(self, finding_id: str, owner_id: str) -> FindingRemediation:
        finding = self._get_finding_for_owner(finding_id, owner_id)
        record = self.session.query(FindingRemediation).filter(FindingRemediation.finding_id == finding.id).one_or_none()
        if record is None:
            record = self.create(finding_id, owner_id, remediation_notes=None)
        return record

    def create(self, finding_id: str, owner_id: str, remediation_notes: str | None = None) -> FindingRemediation:
        finding = self._get_finding_for_owner(finding_id, owner_id)
        existing = self.session.query(FindingRemediation).filter(FindingRemediation.finding_id == finding.id).one_or_none()
        if existing is not None:
            if remediation_notes is not None and remediation_notes.strip():
                existing.remediation_notes = remediation_notes.strip()
                existing.updated_at = utcnow()
                self.session.commit()
            return existing

        record = FindingRemediation(
            finding_id=finding.id,
            business_id=finding.scan.website.business_id,
            website_id=finding.website_id,
            user_id=owner_id,
            status='open',
            remediation_notes=remediation_notes.strip() if remediation_notes else None,
            started_at=None,
            completed_at=None,
            verification_requested_at=None,
            verified_at=None,
            verification_scan_id=None,
            verification_result=None,
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def update(self, finding_id: str, owner_id: str, payload: dict) -> FindingRemediation:
        record = self.get(finding_id, owner_id)
        if 'status' in payload and payload.get('status') is not None:
            next_status = str(payload['status']).strip().lower()
            if next_status not in VALID_REMEDIATION_STATUSES:
                raise HTTPException(status_code=422, detail='Unsupported remediation status.')
            allowed = VALID_TRANSITIONS.get(record.status, set())
            if next_status not in allowed:
                raise HTTPException(status_code=409, detail=f'Invalid remediation transition: {record.status} -> {next_status}.')
            record.status = next_status
            if next_status == 'in_progress' and record.started_at is None:
                record.started_at = utcnow()
            if next_status == 'pending_verification' and record.verification_requested_at is None:
                record.verification_requested_at = utcnow()
            if next_status == 'resolved':
                record.completed_at = utcnow()
                record.verified_at = record.verified_at or utcnow()
                if record.verification_result is None:
                    record.verification_result = 'user_marked_complete'
            elif next_status != 'resolved':
                record.completed_at = None
        if 'remediation_notes' in payload:
            value = payload.get('remediation_notes')
            record.remediation_notes = value.strip() if value is not None and value.strip() else None
        if 'verification_result' in payload:
            value = payload.get('verification_result')
            record.verification_result = str(value).strip() if value is not None and str(value).strip() else None
        record.updated_at = utcnow()
        self.session.commit()
        return record

    def verify(self, finding_id: str, owner_id: str) -> FindingRemediation:
        finding = self._get_finding_for_owner(finding_id, owner_id)
        record = self.session.query(FindingRemediation).filter(FindingRemediation.finding_id == finding.id).one_or_none()
        if record is None:
            record = self.create(finding_id, owner_id)

        if record.status not in {'in_progress', 'open', 'pending_verification'}:
            if record.status == 'resolved':
                return record
            raise HTTPException(status_code=409, detail='This finding is not ready for verification.')

        record.status = 'pending_verification'
        record.verification_requested_at = utcnow()
        record.updated_at = utcnow()
        self.session.commit()

        scan = Scan(
            website_id=finding.website_id,
            status='queued',
            scan_type='verification',
            started_at=utcnow(),
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        self.session.add(scan)
        self.session.commit()
        self.session.refresh(scan)

        try:
            engine = ScannerEngine(self.session)
            run_method = getattr(engine, 'run')
            try:
                run_method(scan)
            except TypeError:
                attached = self.session.object_session(scan)
                if attached is not None:
                    attached.expunge(scan)
                scan_runner = getattr(ScannerEngine, 'run')
                scan_runner(scan)
        except Exception:
            record.status = 'in_progress'
            record.verification_result = 'scanner_unavailable'
            record.verification_scan_id = scan.id
            record.updated_at = utcnow()
            self.session.commit()
            raise HTTPException(status_code=503, detail='Verification scan could not complete. Please retry later.')

        current = self.session.query(Finding).filter(
            Finding.website_id == finding.website_id,
            Finding.fingerprint == finding.fingerprint,
            Finding.scan_id == scan.id,
        ).one_or_none()

        if current is not None:
            record.status = 'in_progress'
            record.verification_result = 'still_present'
            record.verification_scan_id = scan.id
            record.verified_at = utcnow()
            record.updated_at = utcnow()
            self.session.commit()
            return record

        finding.status = 'resolved'
        finding.resolved_at = utcnow()
        finding.updated_at = utcnow()
        record.status = 'resolved'
        record.completed_at = utcnow()
        record.verification_result = 'resolved'
        record.verification_scan_id = scan.id
        record.verified_at = utcnow()
        record.updated_at = utcnow()
        self.session.commit()
        return record
