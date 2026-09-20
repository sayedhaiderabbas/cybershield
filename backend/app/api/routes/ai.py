from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_id
from app.db.session import get_db
from app.schemas import AIExplainRequest, AIResponseSchema, AIResponseSummary
from app.services.ai_service import AIService

router = APIRouter(prefix='/api/v1', tags=['ai'])


@router.post('/ai/explain')
def explain_finding(
    payload: AIExplainRequest,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    result = AIService(db).explain(payload.finding_id, owner_id)
    return {'data': AIResponseSchema.model_validate(result), 'meta': {'request_id': payload.finding_id}}


@router.post('/ai/remediation')
def remediation_guidance(
    payload: AIExplainRequest,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    result = AIService(db).remediation(payload.finding_id, owner_id)
    return {'data': AIResponseSchema.model_validate(result), 'meta': {'request_id': payload.finding_id}}
