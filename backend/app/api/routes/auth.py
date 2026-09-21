from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_request_context
from app.db.session import get_db
from app.models.entities import TokenRevocation, User
from app.core.security import decode_access_token, get_bearer_token
from app.schemas import UserCreate, UserLogin, UserResponse
from app.services.audit_service import AuditEventService
from app.services.auth_service import AuthService

router = APIRouter(prefix='/api/v1/auth', tags=['auth'])


@router.post('/register', status_code=status.HTTP_201_CREATED)
def register_user(payload: UserCreate, db: Session = Depends(get_db)) -> dict:
    user = AuthService(db).register(payload.email, payload.password, payload.full_name)
    return {'data': UserResponse.model_validate(user)}


@router.post('/login')
def login_user(request: Request, payload: UserLogin, db: Session = Depends(get_db)) -> dict:
    request_id = get_request_context(request)['request_id']
    try:
        user, token = AuthService(db).login(payload.email, payload.password)
    except Exception:
        AuditEventService(db).record_event(
            event_type='AUTHENTICATION',
            action='LOGIN_FAILURE',
            message='User login attempt failed.',
            actor_user_id=None,
            resource_type='auth',
            resource_id='login',
            outcome='FAILURE',
            severity='low',
            request_id=request_id,
            metadata={'email_domain': payload.email.split('@')[-1] if '@' in payload.email else payload.email},
        )
        raise
    AuditEventService(db).record_event(
        event_type='AUTHENTICATION',
        action='LOGIN_SUCCESS',
        message='User signed in successfully.',
        actor_user_id=user.id,
        resource_type='user',
        resource_id=user.id,
        outcome='SUCCESS',
        severity='info',
        request_id=request_id,
        metadata={'email': user.email},
    )
    return {
        'data': {
            'token': token,
            'token_type': 'bearer',
            'user': UserResponse.model_validate(user),
        }
    }


@router.post('/logout')
def logout_user(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)) -> dict:
    request_id = get_request_context(request)['request_id']
    token = get_bearer_token(request.headers.get('Authorization'))
    if token is not None:
        payload = decode_access_token(token)
        token_id = payload.get('jti')
        expires_at = datetime.fromtimestamp(int(payload['exp']), tz=timezone.utc)
        if token_id and db.query(TokenRevocation).filter(TokenRevocation.jti == token_id).first() is None:
            db.add(TokenRevocation(jti=token_id, user_id=current_user.id, expires_at=expires_at, reason='logout'))
            db.commit()
    AuditEventService(db).record_event(
        event_type='AUTHENTICATION',
        action='LOGOUT',
        message='User logged out successfully.',
        actor_user_id=current_user.id,
        resource_type='user',
        resource_id=current_user.id,
        outcome='SUCCESS',
        severity='info',
        request_id=request_id,
    )
    return {
        'data': {
            'message': 'Logout successful. The authentication token has been revoked server-side.',
            'user_id': current_user.id,
        }
    }


@router.get('/me')
def current_user(current_user: User = Depends(get_current_user)) -> dict:
    return {'data': UserResponse.model_validate(current_user)}
