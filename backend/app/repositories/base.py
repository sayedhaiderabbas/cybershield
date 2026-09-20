from __future__ import annotations

from typing import Any, TypeVar

from sqlalchemy import select
from sqlalchemy.orm import Session

ModelT = TypeVar('ModelT')


class BaseRepository:
    model: Any

    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, instance: Any) -> Any:
        self.session.add(instance)
        return instance

    def commit(self) -> None:
        self.session.commit()

    def refresh(self, instance: Any) -> None:
        self.session.refresh(instance)

    def get_by_id(self, item_id: str) -> Any | None:
        return self.session.get(self.model, item_id)

    def list(self, **filters: Any) -> list[Any]:
        stmt = select(self.model)
        for key, value in filters.items():
            if value is not None:
                stmt = stmt.where(getattr(self.model, key) == value)
        return self.session.execute(stmt).scalars().all()
