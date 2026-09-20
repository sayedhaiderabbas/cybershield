from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_id, get_request_context
from app.db.session import get_db
from app.models.entities import Finding, Website
from app.schemas import FindingDetailResponse, FindingRemediationCreate, FindingRemediationResponse, FindingRemediationUpdate, FindingResponse, FindingUpdate
from app.services.audit_service import AuditEventService
from app.services.finding_service import FindingService
from app.services.remediation_service import FindingRemediationService

router = APIRouter(prefix='/api/v1', tags=['findings'])


@router.get('/findings')
def list_findings(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    website_id: str | None = None,
    scan_id: str | None = None,
    sort_by: str = Query(default='last_seen', pattern='^(severity|last_seen|created_at)$'),
    order: str = Query(default='desc', pattern='^(asc|desc)$'),
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    items, total = FindingService(db).list(
        owner_id,
        page,
        page_size,
        severity=severity,
        status=status,
        category=category,
        website_id=website_id,
        scan_id=scan_id,
        sort_by=sort_by,
        order=order,
    )
    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        'data': [FindingResponse.model_validate(item) for item in items],
        'meta': {'page': page, 'page_size': page_size, 'total': total, 'total_pages': total_pages},
    }


@router.get('/findings/{finding_id}')
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    finding = FindingService(db).get(finding_id, owner_id)
    return {
        'data': FindingDetailResponse.model_validate({
            **FindingResponse.model_validate(finding).model_dump(),
            'website_name': finding.scan.website.name,
            'website_url': finding.scan.website.url,
            'scan_status': finding.scan.status,
            'scan_type': finding.scan.scan_type,
            'scan_completed_at': finding.scan.completed_at,
        }),
        'meta': {'request_id': finding_id},
    }


@router.patch('/findings/{finding_id}')
def update_finding(
    finding_id: str,
    request: Request,
    payload: FindingUpdate,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    existing = FindingService(db).get(finding_id, owner_id)
    finding = FindingService(db).update(finding_id, owner_id, payload.model_dump(exclude_unset=True))
    request_id = get_request_context(request)['request_id']
    if payload.status:
        website = db.query(Website).filter(Website.id == finding.website_id).one()
        AuditEventService(db).record_event(
            event_type='FINDINGS',
            action='FINDING_STATUS_CHANGED',
            message='A finding status was changed.',
            actor_user_id=owner_id,
            business_id=website.business_id,
            resource_type='finding',
            resource_id=finding_id,
            outcome='SUCCESS',
            severity=finding.severity,
            request_id=request_id,
            metadata={'previous_status': existing.status, 'new_status': finding.status},
        )
    return {'data': FindingResponse.model_validate(finding), 'meta': {'request_id': finding_id}}


@router.post('/findings/{finding_id}/remediation')
def create_finding_remediation(
    finding_id: str,
    request: Request,
    payload: FindingRemediationCreate | None = None,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    notes = payload.remediation_notes if payload is not None else None
    finding = FindingService(db).get(finding_id, owner_id)
    remediation = FindingRemediationService(db).create(finding_id, owner_id, notes)
    website = db.query(Website).filter(Website.id == finding.website_id).one()
    request_id = get_request_context(request)['request_id']
    AuditEventService(db).record_event(
        event_type='REMEDIATION',
        action='REMEDIATION_STARTED',
        message='Remediation work started for a finding.',
        actor_user_id=owner_id,
        business_id=website.business_id,
        resource_type='finding',
        resource_id=finding_id,
        outcome='SUCCESS',
        severity=finding.severity,
        request_id=request_id,
        metadata={'remediation_id': remediation.id, 'notes': notes},
    )
    return {'data': FindingRemediationResponse.model_validate(remediation), 'meta': {'request_id': finding_id}}


@router.get('/findings/{finding_id}/remediation')
def get_finding_remediation(
    finding_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    remediation = FindingRemediationService(db).get(finding_id, owner_id)
    return {'data': FindingRemediationResponse.model_validate(remediation), 'meta': {'request_id': finding_id}}


@router.patch('/findings/{finding_id}/remediation')
def update_finding_remediation(
    finding_id: str,
    request: Request,
    payload: FindingRemediationUpdate,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    remediation = FindingRemediationService(db).get(finding_id, owner_id)
    updated = FindingRemediationService(db).update(finding_id, owner_id, payload.model_dump(exclude_unset=True))
    finding = FindingService(db).get(finding_id, owner_id)
    website = db.query(Website).filter(Website.id == finding.website_id).one()
    request_id = get_request_context(request)['request_id']
    if payload.status:
        action = 'REMEDIATION_UPDATED'
        message = 'Remediation status was updated.'
        if payload.status == 'pending_verification':
            action = 'VERIFICATION_REQUESTED'
            message = 'Verification was requested for the remediation activity.'
        AuditEventService(db).record_event(
            event_type='REMEDIATION',
            action=action,
            message=message,
            actor_user_id=owner_id,
            business_id=website.business_id,
            resource_type='finding',
            resource_id=finding_id,
            outcome='SUCCESS',
            severity=finding.severity,
            request_id=request_id,
            metadata={'previous_status': remediation.status, 'new_status': payload.status, 'remediation_id': updated.id},
        )
    return {'data': FindingRemediationResponse.model_validate(updated), 'meta': {'request_id': finding_id}}


@router.post('/findings/{finding_id}/remediation/verify')
def verify_finding_remediation(
    finding_id: str,
    request: Request,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    finding = FindingService(db).get(finding_id, owner_id)
    remediation = FindingRemediationService(db).verify(finding_id, owner_id)
    website = db.query(Website).filter(Website.id == finding.website_id).one()
    request_id = get_request_context(request)['request_id']
    AuditEventService(db).record_event(
        event_type='REMEDIATION',
        action='VERIFICATION_COMPLETED',
        message='Verification against the live scan completed.',
        actor_user_id=owner_id,
        business_id=website.business_id,
        resource_type='finding',
        resource_id=finding_id,
        outcome='SUCCESS',
        severity=finding.severity,
        request_id=request_id,
        metadata={'verification_result': remediation.verification_result, 'scan_id': remediation.verification_scan_id},
    )
    return {'data': FindingRemediationResponse.model_validate(remediation), 'meta': {'request_id': finding_id}}
