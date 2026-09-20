from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_id
from app.db.session import get_db
from app.schemas import BusinessCreate, BusinessResponse, BusinessUpdate, PaginationQuery
from app.services.business_service import BusinessService

router = APIRouter(prefix='/api/v1', tags=['businesses'])


@router.post('/businesses', status_code=201)
def create_business(
    payload: BusinessCreate,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    business = BusinessService(db).create(owner_id, payload)
    return {'data': BusinessResponse.model_validate(business), 'meta': {'request_id': owner_id}}


@router.get('/businesses')
def list_businesses(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    items, total = BusinessService(db).list(owner_id, page, page_size)
    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        'data': [BusinessResponse.model_validate(item) for item in items],
        'meta': {'page': page, 'page_size': page_size, 'total': total, 'total_pages': total_pages},
    }


@router.get('/businesses/{business_id}')
def get_business(
    business_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    business = BusinessService(db).get(business_id, owner_id)
    return {'data': BusinessResponse.model_validate(business), 'meta': {'request_id': business_id}}


@router.patch('/businesses/{business_id}')
def update_business(
    business_id: str,
    payload: BusinessUpdate,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    business = BusinessService(db).update(business_id, owner_id, payload)
    return {'data': BusinessResponse.model_validate(business), 'meta': {'request_id': business_id}}


@router.delete('/businesses/{business_id}', status_code=204)
def delete_business(
    business_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> Response:
    BusinessService(db).delete(business_id, owner_id)
    return Response(status_code=204)
