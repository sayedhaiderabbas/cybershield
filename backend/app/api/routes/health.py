from __future__ import annotations

from fastapi import APIRouter
from fastapi import HTTPException
from sqlalchemy import text

from app.db.session import engine

router = APIRouter()


@router.get('/health')
def health() -> dict[str, str]:
    return {'status': 'ok'}


@router.get('/ready')
def ready() -> dict[str, str]:
    try:
        with engine.connect() as connection:
            connection.execute(text('SELECT 1'))
    except Exception as exc:
        raise HTTPException(status_code=503, detail='The service is not ready.') from exc
    return {'status': 'ready'}


@router.get('/api/v1')
def api_root() -> dict[str, str]:
    return {
        'service': 'CyberShield',
        'version': 'v1',
        'status': 'operational',
    }
