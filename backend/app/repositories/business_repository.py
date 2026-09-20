from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Business
from app.repositories.base import BaseRepository


class BusinessRepository(BaseRepository):
    model = Business

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def list_for_owner(self, owner_id: str, page: int | None = None, page_size: int | None = None) -> list[Business]:
        stmt = select(Business).where(Business.owner_id == owner_id).order_by(Business.created_at.desc(), Business.id.desc())
        if page is not None and page_size is not None:
            stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        return self.session.execute(stmt).scalars().all()

    def count_for_owner(self, owner_id: str) -> int:
        return self.session.query(Business).filter(Business.owner_id == owner_id).count()

    def get_for_owner(self, business_id: str, owner_id: str) -> Business | None:
        stmt = select(Business).where(Business.id == business_id, Business.owner_id == owner_id)
        return self.session.execute(stmt).scalar_one_or_none()
