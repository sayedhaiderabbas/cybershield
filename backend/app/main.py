from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from app.api.routes.ai import router as ai_router
from app.api.routes.alerts import router as alerts_router
from app.api.routes.audit import router as audit_router
from app.api.routes.auth import router as auth_router
from app.api.routes.businesses import router as businesses_router
from app.api.routes.findings import router as findings_router
from app.api.routes.health import router as health_router
from app.api.routes.monitoring import router as monitoring_router
from app.api.routes.reports import router as reports_router
from app.api.routes.scans import router as scans_router
from app.api.routes.security import router as security_router
from app.api.routes.websites import router as websites_router
from app.core.config import get_settings
from app.core.errors import ApiError, error_payload
from app.core.logging import configure_logging
from app.db.base import Base
from app.db.session import engine, init_db
from app.services.monitoring_service import monitoring_scheduler

settings = get_settings()
logger = configure_logging(settings.log_level)

app = FastAPI(
    title='CyberShield API',
    version='0.1.0',
    description='Safe-by-design backend architecture for CyberShield.',
    docs_url='/docs',
    openapi_url='/openapi.json',
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowlist,
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(ai_router)
app.include_router(audit_router)
app.include_router(alerts_router)
app.include_router(businesses_router)
app.include_router(websites_router)
app.include_router(scans_router)
app.include_router(findings_router)
app.include_router(security_router)
app.include_router(reports_router)
app.include_router(monitoring_router)


@app.middleware('http')
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src 'self' data: https://fastapi.tiangolo.com; "
        "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
    )
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    if settings.app_env.lower() in {'production', 'prod'} and request.url.scheme == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.on_event('startup')
def startup() -> None:
    init_db()
    monitoring_scheduler.start()


@app.get('/')
def root() -> dict[str, str]:
    return {'service': 'CyberShield', 'status': 'booting'}


@app.exception_handler(ApiError)
async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    logger.warning('api_error %s %s %s', request.method, request.url.path, exc.code)
    return JSONResponse(status_code=exc.status_code, content=error_payload(exc))


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    logger.warning('validation_error %s %s', request.method, request.url.path)

    sanitized_details: list[dict[str, object]] = []
    for error in exc.errors():
        cleaned: dict[str, object] = {
            'loc': list(error.get('loc', ())),
            'msg': str(error.get('msg', 'Validation failed.')),
            'type': str(error.get('type', 'validation_error')),
        }
        ctx = error.get('ctx')
        if isinstance(ctx, dict):
            cleaned['ctx'] = {key: str(value) for key, value in ctx.items()}
        sanitized_details.append(cleaned)

    return JSONResponse(
        status_code=422,
        content={
            'error': {
                'code': 'VALIDATION_ERROR',
                'message': 'The request could not be processed.',
                'details': sanitized_details,
            }
        },
    )


@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception('Unhandled backend error %s %s', request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': 'An internal server error occurred.',
                'details': [],
            }
        },
    )
