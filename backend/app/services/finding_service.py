from __future__ import annotations

from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.entities import Finding, Scan, Website
from app.repositories.finding_repository import FindingRepository
from app.services.base import ensure_entity

VALID_FINDING_STATUSES = {'open', 'acknowledged', 'resolved'}


def normalize_severity(value: str | None) -> str:
    mapping = {'info': 'info', 'informational': 'info', 'low': 'low', 'medium': 'medium', 'moderate': 'medium', 'high': 'high', 'critical': 'critical'}
    if value is None:
        return 'info'
    return mapping.get(str(value).strip().lower(), 'info')


def priority_for_severity(value: str) -> str:
    normalized = normalize_severity(value)
    return {
        'critical': 'immediate',
        'high': 'high',
        'medium': 'normal',
        'low': 'low',
        'info': 'informational',
    }.get(normalized, 'informational')


def fingerprint_for_finding(website_id: str, check_id: str, category: str) -> str:
    return f'{website_id}:{check_id}:{category}'


class FindingService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.repo = FindingRepository(session)

    def list(
        self,
        owner_id: str,
        page: int,
        page_size: int,
        severity: str | None = None,
        status: str | None = None,
        category: str | None = None,
        website_id: str | None = None,
        scan_id: str | None = None,
        sort_by: str = 'last_seen',
        order: str = 'desc',
    ) -> tuple[list[Finding], int]:
        if website_id is not None:
            website = self.session.query(Website).join(Website.business).filter(Website.id == website_id, Website.business.has(owner_id=owner_id)).one_or_none()
            if website is None:
                raise HTTPException(status_code=403, detail='Website access denied.')
        if scan_id is not None:
            scan = self.session.query(Scan).join(Scan.website).join(Website.business).filter(Scan.id == scan_id, Website.business.has(owner_id=owner_id)).one_or_none()
            if scan is None:
                raise HTTPException(status_code=403, detail='Scan access denied.')
        normalized_severity = normalize_severity(severity) if severity is not None else None
        valid_sort = sort_by if sort_by in {'severity', 'created_at', 'last_seen'} else 'last_seen'
        valid_order = order if order in {'asc', 'desc'} else 'desc'
        items, total = self.repo.list_filtered(
            severity=normalized_severity,
            status=status,
            category=category,
            website_id=website_id,
            scan_id=scan_id,
            sort_by=valid_sort,
            order=valid_order,
            owner_id=owner_id,
            page=page,
            page_size=page_size,
        )
        return items, total

    def get(self, finding_id: str, owner_id: str) -> Finding:
        finding = self.session.query(Finding).join(Scan).join(Website).join(Website.business).filter(Finding.id == finding_id, Website.business.has(owner_id=owner_id)).one_or_none()
        ensure_entity(finding, 'Finding not found.')
        return finding

    def update(self, finding_id: str, owner_id: str, payload: dict) -> Finding:
        finding = self.get(finding_id, owner_id)
        if 'status' in payload and payload['status'] is not None:
            status_value = str(payload['status']).strip().lower()
            if status_value not in VALID_FINDING_STATUSES:
                raise HTTPException(status_code=422, detail='Unsupported finding status.')
            finding.status = status_value
            if status_value == 'resolved':
                finding.resolved_at = datetime.utcnow()
            elif status_value != 'resolved':
                finding.resolved_at = None
            finding.priority = priority_for_severity(finding.severity)
        finding.updated_at = datetime.utcnow()
        self.repo.commit()
        return finding
