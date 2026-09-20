from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import MonitoringTarget
from app.repositories.base import BaseRepository


class MonitoringRepository(BaseRepository):
    model = MonitoringTarget

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def list_for_business(self, business_id: str) -> list[MonitoringTarget]:
        stmt = select(MonitoringTarget).where(MonitoringTarget.business_id == business_id).order_by(MonitoringTarget.created_at.desc())
        return self.session.execute(stmt).scalars().all()

    def get_for_business(self, monitoring_id: str, business_id: str) -> MonitoringTarget | None:
        stmt = select(MonitoringTarget).where(MonitoringTarget.id == monitoring_id, MonitoringTarget.business_id == business_id)
        return self.session.execute(stmt).scalar_one_or_none()
