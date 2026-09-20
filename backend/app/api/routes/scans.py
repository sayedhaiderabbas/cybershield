from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_id, get_request_context
from app.db.session import get_db
from app.models.entities import Finding, Website
from app.schemas import FindingResponse, ScanCreate, ScanResponse
from app.services.audit_service import AuditEventService
from app.services.scan_service import ScanService

router = APIRouter(prefix='/api/v1', tags=['scans'])


@router.post('/scans', status_code=201)
def create_scan(
    request: Request,
    payload: ScanCreate,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    website = db.query(Website).filter(Website.id == payload.website_id).one()
    scan = ScanService(db).create(owner_id, payload)
    request_id = get_request_context(request)['request_id']
    AuditEventService(db).record_event(
        event_type='SCANNING',
        action='SCAN_CREATED',
        message='A security scan was started for the website.',
        actor_user_id=owner_id,
        business_id=website.business_id,
        resource_type='scan',
        resource_id=scan.id,
        outcome='SUCCESS',
        severity='info',
        request_id=request_id,
    )
    return {'data': {'scan_id': scan.id, 'status': scan.status, 'website_id': scan.website_id}, 'meta': {'request_id': scan.id}}


@router.get('/scans')
def list_scans(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    items, total = ScanService(db).list(owner_id, page, page_size)
    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        'data': [ScanResponse.model_validate(item) for item in items],
        'meta': {'page': page, 'page_size': page_size, 'total': total, 'total_pages': total_pages},
    }


@router.get('/scans/{scan_id}')
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    scan = ScanService(db).get(scan_id, owner_id)
    return {'data': ScanResponse.model_validate(scan), 'meta': {'request_id': scan_id}}


@router.get('/scans/{scan_id}/status')
def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    scan = ScanService(db).get_status(scan_id, owner_id)
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).count()
    return {
        'data': {
            'id': scan.id,
            'status': scan.status,
            'started_at': scan.started_at,
            'completed_at': scan.completed_at,
            'risk_score': scan.risk_score,
            'finding_count': findings,
        },
        'meta': {'request_id': scan_id},
    }


@router.get('/scans/{scan_id}/findings')
def get_scan_findings(
    scan_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    scan = ScanService(db).get(scan_id, owner_id)
    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    return {'data': [FindingResponse.model_validate(item).model_dump() for item in findings], 'meta': {'request_id': scan_id}}
