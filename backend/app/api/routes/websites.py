from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_id, get_request_context
from app.db.session import get_db
from app.schemas import WebsiteCreate, WebsiteResponse, WebsiteUpdate
from app.services.audit_service import AuditEventService
from app.services.website_service import WebsiteService

router = APIRouter(prefix='/api/v1', tags=['websites'])


@router.post('/websites', status_code=201)
def create_website(
    request: Request,
    payload: WebsiteCreate,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    website = WebsiteService(db).create(owner_id, payload)
    request_id = get_request_context(request)['request_id']
    AuditEventService(db).record_event(
        event_type='WEBSITE',
        action='WEBSITE_CREATED',
        message='Website was added to the business.',
        actor_user_id=owner_id,
        business_id=payload.business_id,
        resource_type='website',
        resource_id=website.id,
        outcome='SUCCESS',
        severity='info',
        request_id=request_id,
    )
    return {'data': WebsiteResponse.model_validate(website), 'meta': {'request_id': website.id}}


@router.get('/websites')
def list_websites(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    items, total = WebsiteService(db).list(owner_id, page, page_size)
    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        'data': [WebsiteResponse.model_validate(item) for item in items],
        'meta': {'page': page, 'page_size': page_size, 'total': total, 'total_pages': total_pages},
    }


@router.get('/websites/{website_id}')
def get_website(
    website_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    website = WebsiteService(db).get(website_id, owner_id)
    return {'data': WebsiteResponse.model_validate(website), 'meta': {'request_id': website_id}}


@router.patch('/websites/{website_id}')
def update_website(
    website_id: str,
    request: Request,
    payload: WebsiteUpdate,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    website = WebsiteService(db).get(website_id, owner_id)
    updated_website = WebsiteService(db).update(website_id, owner_id, payload)
    request_id = get_request_context(request)['request_id']
    AuditEventService(db).record_event(
        event_type='WEBSITE',
        action='WEBSITE_UPDATED',
        message='Website configuration was updated.',
        actor_user_id=owner_id,
        business_id=website.business_id,
        resource_type='website',
        resource_id=website_id,
        outcome='SUCCESS',
        severity='info',
        request_id=request_id,
    )
    return {'data': WebsiteResponse.model_validate(updated_website), 'meta': {'request_id': website_id}}


@router.delete('/websites/{website_id}', status_code=204)
def delete_website(
    website_id: str,
    request: Request,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> Response:
    website = WebsiteService(db).get(website_id, owner_id)
    WebsiteService(db).delete(website_id, owner_id)
    request_id = get_request_context(request)['request_id']
    AuditEventService(db).record_event(
        event_type='WEBSITE',
        action='WEBSITE_DELETED',
        message='Website was removed from the business.',
        actor_user_id=owner_id,
        business_id=website.business_id,
        resource_type='website',
        resource_id=website_id,
        outcome='SUCCESS',
        severity='medium',
        request_id=request_id,
    )
    return Response(status_code=204)
