from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import Report
from app.repositories.base import BaseRepository


class ReportRepository(BaseRepository):
    model = Report

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def list_for_business(self, business_id: str) -> list[Report]:
        stmt = select(Report).where(Report.business_id == business_id).order_by(Report.created_at.desc())
        return self.session.execute(stmt).scalars().all()
