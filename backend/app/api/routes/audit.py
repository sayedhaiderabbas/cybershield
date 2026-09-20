from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_id, get_request_context
from app.db.session import get_db
from app.schemas import SecurityEventResponse
from app.services.audit_service import AuditEventService

router = APIRouter(prefix='/api/v1', tags=['audit'])


def _serialize_event(item) -> SecurityEventResponse:
    return SecurityEventResponse(
        id=item.id,
        actor_user_id=item.actor_user_id,
        business_id=item.business_id,
        event_type=item.event_type,
        action=item.action,
        resource_type=item.resource_type,
        resource_id=item.resource_id,
        outcome=item.outcome,
        severity=item.severity,
        message=item.message,
        request_id=item.request_id,
        details=item.event_details,
        created_at=item.created_at,
    )


@router.get('/audit-events')
def list_audit_events(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    event_type: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    outcome: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    items, total = AuditEventService(db).list_events(
        owner_id,
        page=page,
        page_size=page_size,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        start_date=start_date,
        end_date=end_date,
    )
    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        'data': [_serialize_event(item) for item in items],
        'meta': {'page': page, 'page_size': page_size, 'total': total, 'total_pages': total_pages, 'request_id': get_request_context(request)['request_id']},
    }


@router.get('/audit/events')
def list_audit_events_alias(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    event_type: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    outcome: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    return list_audit_events(
        request=request,
        page=page,
        page_size=page_size,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        start_date=start_date,
        end_date=end_date,
        db=db,
        owner_id=owner_id,
    )
