from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_id, get_request_context
from app.db.session import get_db
import json

from app.schemas import AlertResponse, AlertUpdate
from app.services.alert_service import AlertService
from app.services.audit_service import AuditEventService

router = APIRouter(prefix='/api/v1', tags=['alerts'])

def serialize_alert(alert) -> AlertResponse:
    metadata = {}
    if alert.alert_metadata:
        try:
            parsed = json.loads(alert.alert_metadata)
            if isinstance(parsed, dict):
                metadata = parsed
        except (TypeError, ValueError):
            metadata = {}
    website = alert.website
    finding = None
    if alert.finding_id:
        finding = alert.finding
    current_scan = alert.scan
    previous_score = metadata.get('previous_risk_score')
    current_score = metadata.get('current_risk_score')
    if current_score is None and current_scan is not None:
        current_score = current_scan.risk_score
    safe_evidence = []
    if finding is not None:
        safe_evidence = [finding.evidence] if finding.evidence else []
    elif metadata.get('fingerprint'):
        safe_evidence = [f"Finding fingerprint: {metadata['fingerprint']}"]
    return AlertResponse.model_validate({
        **{field: getattr(alert, field) for field in (
            'id', 'business_id', 'website_id', 'monitoring_id', 'scan_id',
            'finding_id', 'alert_type', 'severity', 'title', 'message',
            'status', 'deduplication_key', 'alert_metadata', 'created_at',
            'updated_at', 'acknowledged_at', 'resolved_at',
        )},
        'website_name': website.name if website is not None else None,
        'finding_reference': finding.references if finding is not None else metadata.get('fingerprint'),
        'safe_evidence': safe_evidence,
        'previous_risk_score': previous_score,
        'current_risk_score': current_score,
        'risk_delta': (
            float(current_score) - float(previous_score)
            if previous_score is not None and current_score is not None else metadata.get('risk_delta')
        ),
    })


@router.get('/alerts')
def list_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: str | None = None,
    severity: str | None = None,
    alert_type: str | None = None,
    website_id: str | None = None,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    items, total = AlertService(db).list(owner_id, page, page_size, status=status, severity=severity, alert_type=alert_type, website_id=website_id)
    total_pages = (total + page_size - 1) // page_size if total else 0
    return {
        'data': [serialize_alert(item) for item in items],
        'meta': {'page': page, 'page_size': page_size, 'total': total, 'total_pages': total_pages},
    }


@router.get('/alerts/unread-count')
def get_unread_alert_count(
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    count = AlertService(db).get_unread_count(owner_id)
    return {'data': {'count': count}, 'meta': {'request_id': owner_id}}


@router.get('/alerts/summary')
def get_alert_summary(
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    return {'data': AlertService(db).get_summary(owner_id), 'meta': {'request_id': owner_id}}


@router.get('/alerts/{alert_id}')
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    alert = AlertService(db).get_alert(alert_id, owner_id)
    return {'data': serialize_alert(alert), 'meta': {'request_id': alert_id}}


@router.patch('/alerts/{alert_id}')
def update_alert(
    alert_id: str,
    request: Request,
    payload: AlertUpdate,
    db: Session = Depends(get_db),
    owner_id: str = Depends(get_current_user_id),
) -> dict:
    existing = AlertService(db).get_alert(alert_id, owner_id)
    alert = AlertService(db).update_alert_status(alert_id, owner_id, payload.model_dump(exclude_unset=True))
    request_id = get_request_context(request)['request_id']
    if payload.status in {'acknowledged', 'resolved'}:
        action = 'ALERT_ACKNOWLEDGED' if payload.status == 'acknowledged' else 'ALERT_RESOLVED'
        AuditEventService(db).record_event(
            event_type='ALERTS',
            action=action,
            message=f'Alert {payload.status} by the user.',
            actor_user_id=owner_id,
            business_id=existing.business_id,
            resource_type='alert',
            resource_id=alert_id,
            outcome='SUCCESS',
            severity=alert.severity,
            request_id=request_id,
            metadata={'previous_status': existing.status, 'new_status': alert.status},
        )
    return {'data': serialize_alert(alert), 'meta': {'request_id': alert_id}}
