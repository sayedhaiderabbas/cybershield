from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_id, get_request_context
from app.db.session import get_db
from app.schemas import ReportCreate, ReportResponse
from app.services.audit_service import AuditEventService
from app.services.report_service import ReportService

router = APIRouter(prefix='/api/v1', tags=['reports'])


@router.post('/reports', status_code=201)
def create_report(
    request: Request,
    payload: ReportCreate,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    report = ReportService(db).create(owner_id, payload)
    request_id = get_request_context(request)['request_id']
    AuditEventService(db).record_event(
        event_type='REPORTS',
        action='REPORT_CREATED',
        message='A security report was created.',
        actor_user_id=owner_id,
        business_id=payload.business_id,
        resource_type='report',
        resource_id=report.id,
        outcome='SUCCESS',
        severity='info',
        request_id=request_id,
    )
    return {'data': ReportService.serialize_report(report), 'meta': {'request_id': report.id}}


@router.get('/reports')
def list_reports(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    search: str | None = Query(default=None, max_length=100),
    website_id: str | None = Query(default=None),
    status: str | None = Query(default=None, max_length=25),
    sort: str = Query(default='newest', pattern='^(newest|oldest|generated|oldest-generated)$'),
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    items, total = ReportService(db).list(
        owner_id,
        page,
        page_size,
        search=search,
        website_id=website_id,
        status=status,
        sort=sort,
    )
    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        'data': [ReportService.serialize_report(item, include_metadata=False) for item in items],
        'meta': {'page': page, 'page_size': page_size, 'total': total, 'total_pages': total_pages},
    }


@router.get('/reports/{report_id}')
def get_report(
    report_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    report = ReportService(db).get(report_id, owner_id)
    return {'data': ReportService.serialize_report(report), 'meta': {'request_id': report_id}}


@router.get('/reports/{report_id}/download')
def download_report(
    report_id: str,
    request: Request,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> FileResponse:
    report = ReportService(db).get(report_id, owner_id)
    file_path = ReportService.resolve_download_path(report)
    if file_path is None:
        raise HTTPException(status_code=404, detail='Report download is not available.')
    request_id = get_request_context(request)['request_id']
    AuditEventService(db).record_event(
        event_type='REPORTS',
        action='REPORT_DOWNLOADED',
        message='A security report was downloaded.',
        actor_user_id=owner_id,
        business_id=report.business_id,
        resource_type='report',
        resource_id=report.id,
        outcome='SUCCESS',
        severity='info',
        request_id=request_id,
    )
    safe_name = f'cybershield-report-{report.id}.pdf'
    return FileResponse(path=file_path, media_type='application/pdf', filename=safe_name)
