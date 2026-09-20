from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Scan
from app.repositories.base import BaseRepository


class ScanRepository(BaseRepository):
    model = Scan

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def list_for_website(self, website_id: str) -> list[Scan]:
        stmt = select(Scan).where(Scan.website_id == website_id).order_by(Scan.created_at.desc())
        return self.session.execute(stmt).scalars().all()

    def get_for_website(self, scan_id: str, website_id: str) -> Scan | None:
        stmt = select(Scan).where(Scan.id == scan_id, Scan.website_id == website_id)
        return self.session.execute(stmt).scalar_one_or_none()
