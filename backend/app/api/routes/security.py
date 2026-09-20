from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_id
from app.db.session import get_db
from app.services.risk_service import RiskService
from app.services.security_posture_service import SecurityPostureService

router = APIRouter(prefix='/api/v1', tags=['security'])


@router.get('/security/overview')
def security_overview(
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    overview = RiskService(db).overview_for_user(owner_id)
    return {'data': overview, 'meta': {'request_id': owner_id}}


@router.get('/security/posture')
def security_posture(
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    posture = SecurityPostureService(db).get_for_user(owner_id)
    return {'data': posture, 'meta': {'request_id': owner_id}}