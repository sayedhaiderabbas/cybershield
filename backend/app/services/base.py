from __future__ import annotations

from typing import Any, TypeVar

from fastapi import HTTPException

T = TypeVar('T')


def ensure_entity(entity: Any, message: str = 'Resource not found.') -> Any:
    if entity is None:
        raise HTTPException(status_code=404, detail=message)
    return entity


def ensure_ownership(belongs: bool, message: str = 'You are not authorized to access this resource.') -> None:
    if not belongs:
        raise HTTPException(status_code=403, detail=message)
