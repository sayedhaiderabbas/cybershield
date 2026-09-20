from __future__ import annotations

from sqlalchemy import case, desc, asc, func, select
from sqlalchemy.orm import Session

from app.models.entities import Business, Finding, Scan, Website
from app.repositories.base import BaseRepository


class FindingRepository(BaseRepository):
    model = Finding

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def list_for_scan(self, scan_id: str) -> list[Finding]:
        stmt = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.last_seen_at.desc())
        return self.session.execute(stmt).scalars().all()

    def list_for_website(self, website_id: str) -> list[Finding]:
        stmt = select(Finding).where(Finding.website_id == website_id).order_by(Finding.last_seen_at.desc())
        return self.session.execute(stmt).scalars().all()

    def list_filtered(
        self,
        *,
        severity: str | None = None,
        status: str | None = None,
        category: str | None = None,
        website_id: str | None = None,
        scan_id: str | None = None,
        sort_by: str = 'last_seen',
        order: str = 'desc',
        owner_id: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
    ) -> tuple[list[Finding], int]:
        stmt = select(Finding).join(Scan).join(Website).join(Business)
        if owner_id is not None:
            stmt = stmt.where(Business.owner_id == owner_id)
        if severity is not None:
            stmt = stmt.where(Finding.severity == severity)
        if status is not None:
            stmt = stmt.where(Finding.status == status)
        if category is not None:
            stmt = stmt.where(Finding.category == category)
        if website_id is not None:
            stmt = stmt.where(Finding.website_id == website_id)
        if scan_id is not None:
            stmt = stmt.where(Finding.scan_id == scan_id)

        severity_order = case(
            (Finding.severity == 'critical', 5),
            (Finding.severity == 'high', 4),
            (Finding.severity == 'medium', 3),
            (Finding.severity == 'low', 2),
            (Finding.severity == 'info', 1),
            else_=0,
        )
        if sort_by == 'severity':
            primary = severity_order.desc() if order == 'desc' else severity_order.asc()
            stmt = stmt.order_by(primary, Finding.last_seen_at.desc(), Finding.id.desc())
        elif sort_by == 'created_at':
            stmt = stmt.order_by(Finding.created_at.desc() if order == 'desc' else Finding.created_at.asc(), Finding.id.desc())
        else:
            stmt = stmt.order_by(Finding.last_seen_at.desc() if order == 'desc' else Finding.last_seen_at.asc(), Finding.id.desc())
        total = self.session.execute(select(func.count()).select_from(stmt.order_by(None).subquery())).scalar_one()
        if page is not None and page_size is not None:
            stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        return self.session.execute(stmt).scalars().all(), total
