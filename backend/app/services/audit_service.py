from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.entities import Business, SecurityEvent, User

ALLOWED_EVENT_TYPES = {
    'AUTHENTICATION',
    'BUSINESS',
    'WEBSITE',
    'SCANNING',
    'FINDINGS',
    'ALERTS',
    'MONITORING',
    'REPORTS',
    'REMEDIATION',
}

SENSITIVE_KEYS = {
    'password', 'password_hash', 'token', 'access_token', 'refresh_token', 'session', 'cookie', 'authorization',
    'api_key', 'apikey', 'secret', 'secret_key', 'jwt', 'bearer', 'credentials', 'auth_header', 'raw_body',
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_event_type(value: str | None) -> str:
    if value is None:
        raise ValueError('event_type is required.')
    normalized = str(value).strip().upper()
    if normalized not in ALLOWED_EVENT_TYPES:
        raise ValueError(f'Unsupported event_type: {value}')
    return normalized


def _sanitize_metadata(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(block in lowered for block in SENSITIVE_KEYS):
                continue
            cleaned[str(key)] = _sanitize_metadata(item)
        return cleaned
    if isinstance(value, list):
        return [_sanitize_metadata(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_metadata(item) for item in value)
    if isinstance(value, str):
        lowered = value.lower()
        if any(block in lowered for block in ('password', 'token', 'cookie', 'authorization', 'api_key', 'secret')):
            return '[REDACTED]'
        if len(value) > 2000:
            return value[:2000]
        return value
    return value


class AuditEventService:
    def __init__(self, db: Session):
        self.db = db

    def record_event(
        self,
        *,
        event_type: str,
        action: str,
        message: str,
        business_id: str | None = None,
        actor_user_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        outcome: str = 'SUCCESS',
        severity: str = 'info',
        request_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SecurityEvent:
        normalized_event_type = _normalize_event_type(event_type)
        normalized_action = str(action or 'ACCESS').strip().upper()
        normalized_outcome = str(outcome).strip().upper() if outcome else 'SUCCESS'
        normalized_severity = str(severity).strip().lower() if severity else 'info'
        cleaned = _sanitize_metadata(metadata or {})

        event = SecurityEvent(
            actor_user_id=actor_user_id,
            business_id=business_id,
            event_type=normalized_event_type,
            action=normalized_action,
            resource_type=(str(resource_type).strip() if resource_type else None),
            resource_id=(str(resource_id).strip() if resource_id else None),
            outcome=normalized_outcome,
            severity=normalized_severity,
            message=message[:2000] if message else 'Security event recorded.',
            request_id=request_id or 'unknown-request',
            event_details=json.dumps(cleaned, sort_keys=True) if cleaned else None,
            created_at=_utc_now(),
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event

    def list_events(
        self,
        owner_id: str,
        *,
        page: int = 1,
        page_size: int = 20,
        event_type: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        outcome: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> tuple[list[SecurityEvent], int]:
        query = self.db.query(SecurityEvent).outerjoin(Business, SecurityEvent.business_id == Business.id).outerjoin(User, SecurityEvent.actor_user_id == User.id).filter(
            or_(Business.owner_id == owner_id, SecurityEvent.actor_user_id == owner_id)
        )

        if event_type:
            query = query.filter(SecurityEvent.event_type == str(event_type).upper())
        if resource_type:
            query = query.filter(SecurityEvent.resource_type == str(resource_type).strip())
        if resource_id:
            query = query.filter(SecurityEvent.resource_id == str(resource_id).strip())
        if outcome:
            query = query.filter(SecurityEvent.outcome == str(outcome).upper())
        if start_date:
            try:
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                query = query.filter(SecurityEvent.created_at >= start_dt)
            except ValueError:
                pass
        if end_date:
            try:
                end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                query = query.filter(SecurityEvent.created_at <= end_dt)
            except ValueError:
                pass

        total = query.count()
        items = query.order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
        return items, total
