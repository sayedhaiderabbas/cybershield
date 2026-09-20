from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Website
from app.repositories.base import BaseRepository


class WebsiteRepository(BaseRepository):
    model = Website

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def list_for_business(self, business_id: str) -> list[Website]:
        stmt = select(Website).where(Website.business_id == business_id).order_by(Website.created_at.desc())
        return self.session.execute(stmt).scalars().all()

    def get_for_business(self, website_id: str, business_id: str) -> Website | None:
        stmt = select(Website).where(Website.id == website_id, Website.business_id == business_id)
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_normalized_url(self, business_id: str, normalized_url: str) -> Website | None:
        stmt = select(Website).where(Website.business_id == business_id, Website.normalized_url == normalized_url)
        return self.session.execute(stmt).scalar_one_or_none()
