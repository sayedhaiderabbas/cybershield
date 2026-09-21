from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import Depends, Request
from jwt import InvalidTokenError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AuthenticationFailedError, AuthenticationRequiredError, AuthorizationDeniedError
from app.core.security import decode_access_token, get_bearer_token
from app.db.session import get_db
from app.models.entities import TokenRevocation, User


def get_request_context(request: Request) -> Dict[str, Any]:
    request_id = request.headers.get('X-Request-ID', 'unknown-request')
    return {
        'request_id': request_id,
        'path': request.url.path,
        'method': request.method,
    }


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    authorization = request.headers.get('Authorization')
    token = get_bearer_token(authorization)
    if token is not None:
        try:
            payload = decode_access_token(token)
        except (InvalidTokenError, ValueError, TypeError):
            raise AuthenticationFailedError('Invalid or expired authentication token.')

        user_id = payload.get('sub')
        if user_id is None:
            raise AuthenticationFailedError('Invalid authentication token.')

        if payload.get('type') != 'access':
            raise AuthorizationDeniedError('Invalid token type.')

        token_id = payload.get('jti')
        if not token_id:
            raise AuthenticationFailedError('Invalid authentication token.')

        revoked = db.query(TokenRevocation).filter(TokenRevocation.jti == token_id).first()
        if revoked is not None:
            raise AuthenticationFailedError('Authentication session has been revoked.')

        user = db.get(User, user_id)
        if user is None:
            raise AuthenticationFailedError('Invalid authentication credentials.')
        if not user.is_active:
            raise AuthorizationDeniedError('This account is inactive.')
        return user

    legacy_user_id = request.headers.get('X-User-ID')
    if legacy_user_id and get_settings().enable_legacy_user_header:
        user = db.get(User, legacy_user_id)
        if user is not None and user.is_active:
            return user
        if user is None:
            raise AuthenticationFailedError('User not found.')
        raise AuthorizationDeniedError('This account is inactive.')

    raise AuthenticationRequiredError('Authentication is required.')


def get_current_user_id(request: Request, db: Session = Depends(get_db)) -> str:
    return get_current_user(request, db).id


def get_api_token() -> str:
    return get_settings().jwt_secret
