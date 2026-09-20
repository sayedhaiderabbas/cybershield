from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_id, get_request_context
from app.db.session import get_db
from app.schemas import MonitoringHistoryEntry, MonitoringTargetCreate, MonitoringTargetResponse, MonitoringTargetUpdate
from app.services.audit_service import AuditEventService
from app.services.monitoring_service import MonitoringService

router = APIRouter(prefix='/api/v1', tags=['monitoring'])


@router.get('/monitoring')
def list_monitoring(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    items, total = MonitoringService(db).list(owner_id, page, page_size)
    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        'data': [MonitoringTargetResponse.model_validate(item) for item in items],
        'meta': {'page': page, 'page_size': page_size, 'total': total, 'total_pages': total_pages},
    }


@router.get('/monitoring/overview')
def get_monitoring_overview(
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    return {
        'data': MonitoringService(db).overview(owner_id),
        'meta': {'request_id': 'monitoring-overview'},
    }


@router.post('/monitoring', status_code=201)
def create_monitoring(
    request: Request,
    payload: MonitoringTargetCreate,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    target = MonitoringService(db).create(owner_id, payload)
    request_id = get_request_context(request)['request_id']
    AuditEventService(db).record_event(
        event_type='MONITORING',
        action='MONITORING_CREATED',
        message='Monitoring was enabled for a website.',
        actor_user_id=owner_id,
        business_id=payload.business_id,
        resource_type='monitoring',
        resource_id=target.id,
        outcome='SUCCESS',
        severity='info',
        request_id=request_id,
    )
    return {'data': MonitoringTargetResponse.model_validate(target), 'meta': {'request_id': target.id}}


@router.get('/monitoring/{target_id}')
def get_monitoring(
    target_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    target = MonitoringService(db).get(target_id, owner_id)
    return {'data': MonitoringTargetResponse.model_validate(target), 'meta': {'request_id': target_id}}


@router.patch('/monitoring/{target_id}')
def update_monitoring(
    target_id: str,
    request: Request,
    payload: MonitoringTargetUpdate,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    existing = MonitoringService(db).get(target_id, owner_id)
    target = MonitoringService(db).update(target_id, owner_id, payload)
    request_id = get_request_context(request)['request_id']
    AuditEventService(db).record_event(
        event_type='MONITORING',
        action='MONITORING_UPDATED',
        message='Monitoring configuration was updated.',
        actor_user_id=owner_id,
        business_id=existing.business_id,
        resource_type='monitoring',
        resource_id=target_id,
        outcome='SUCCESS',
        severity='info',
        request_id=request_id,
        metadata={'previous_schedule': existing.schedule, 'new_schedule': target.schedule, 'enabled': target.enabled},
    )
    return {'data': MonitoringTargetResponse.model_validate(target), 'meta': {'request_id': target_id}}


@router.get('/monitoring/{target_id}/history')
def get_monitoring_history(
    target_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    history, total = MonitoringService(db).get_history_page(target_id, owner_id, page, page_size)
    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        'data': [MonitoringHistoryEntry.model_validate(item) for item in history],
        'meta': {'request_id': target_id, 'page': page, 'page_size': page_size, 'total': total, 'total_pages': total_pages},
    }


@router.get('/monitoring/{target_id}/changes')
def get_monitoring_changes(
    target_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    changes = MonitoringService(db).get_changes(target_id, owner_id)
    return {'data': changes, 'meta': {'request_id': target_id}}


@router.delete('/monitoring/{target_id}', status_code=204)
def delete_monitoring(
    target_id: str,
    request: Request,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> Response:
    existing = MonitoringService(db).get(target_id, owner_id)
    MonitoringService(db).delete(target_id, owner_id)
    request_id = get_request_context(request)['request_id']
    AuditEventService(db).record_event(
        event_type='MONITORING',
        action='MONITORING_DISABLED',
        message='Monitoring was disabled.',
        actor_user_id=owner_id,
        business_id=existing.business_id,
        resource_type='monitoring',
        resource_id=target_id,
        outcome='SUCCESS',
        severity='medium',
        request_id=request_id,
    )
    return Response(status_code=204)
