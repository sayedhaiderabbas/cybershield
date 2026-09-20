from __future__ import annotations

from typing import Any, Dict, List, Optional


class ApiError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 500,
        details: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or []


class ValidationError(ApiError):
    def __init__(self, message: str, details: Optional[List[Dict[str, Any]]] = None) -> None:
        super().__init__('VALIDATION_ERROR', message, 400, details)


class AuthenticationRequiredError(ApiError):
    def __init__(self, message: str = 'Authentication is required.') -> None:
        super().__init__('AUTHENTICATION_REQUIRED', message, 401)


class AuthenticationFailedError(ApiError):
    def __init__(self, message: str = 'Authentication failed.') -> None:
        super().__init__('AUTHENTICATION_FAILED', message, 401)


class AuthorizationDeniedError(ApiError):
    def __init__(self, message: str = 'You are not allowed to access this resource.') -> None:
        super().__init__('AUTHORIZATION_DENIED', message, 403)


class ResourceNotFoundError(ApiError):
    def __init__(self, message: str = 'Resource not found.') -> None:
        super().__init__('RESOURCE_NOT_FOUND', message, 404)


class ResourceConflictError(ApiError):
    def __init__(self, message: str = 'Resource conflict.') -> None:
        super().__init__('RESOURCE_CONFLICT', message, 409)


class RateLimitedError(ApiError):
    def __init__(self, message: str = 'Too many requests.') -> None:
        super().__init__('RATE_LIMITED', message, 429)


class InvalidTargetError(ApiError):
    def __init__(self, message: str = 'The target is not valid for scanning.') -> None:
        super().__init__('INVALID_TARGET', message, 400)


class ScanNotAllowedError(ApiError):
    def __init__(self, message: str = 'This scan is not permitted.') -> None:
        super().__init__('SCAN_NOT_ALLOWED', message, 403)


class ScanFailedError(ApiError):
    def __init__(self, message: str = 'The scan could not complete.') -> None:
        super().__init__('SCAN_FAILED', message, 500)


def error_payload(error: ApiError) -> dict[str, Any]:
    return {
        'error': {
            'code': error.code,
            'message': error.message,
            'details': error.details,
        }
    }
