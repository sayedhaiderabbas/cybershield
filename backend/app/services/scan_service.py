from __future__ import annotations

import logging
import threading
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.entities import Scan, Website
from app.repositories.scan_repository import ScanRepository
from app.repositories.website_repository import WebsiteRepository
from app.scanner.engine import ScannerEngine
from app.schemas import ScanCreate
from app.services.alert_service import AlertService
from app.services.base import ensure_entity

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.repo = ScanRepository(session)
        self.website_repo = WebsiteRepository(session)

    def create(self, owner_id: str, payload: ScanCreate) -> Scan:
        website = self.website_repo.get_for_business(payload.website_id, self._business_id_for_website(owner_id, payload.website_id))
        if website is None:
            raise HTTPException(status_code=403, detail='Website is not owned by the current user.')
        scan = Scan(
            website_id=payload.website_id,
            status='queued',
            scan_type=payload.scan_type,
            started_at=datetime.utcnow(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.repo.add(scan)
        self.repo.commit()
        self.repo.refresh(scan)

        thread = threading.Thread(target=self._execute_in_background, args=(scan.id,), daemon=True)
        thread.start()
        return scan

    def list(self, owner_id: str, page: int, page_size: int) -> tuple[list[Scan], int]:
        query = self.session.query(Scan).join(Website).filter(Website.business.has(owner_id=owner_id))
        total = query.count()
        items = query.order_by(Scan.created_at.desc(), Scan.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
        return items, total

    def get(self, scan_id: str, owner_id: str) -> Scan:
        scan = self.session.query(Scan).join(Website).join(Website.business).filter(Scan.id == scan_id, Website.business.has(owner_id=owner_id)).one_or_none()
        ensure_entity(scan, 'Scan not found.')
        return scan

    def get_status(self, scan_id: str, owner_id: str) -> Scan:
        return self.get(scan_id, owner_id)

    def get_findings(self, scan_id: str, owner_id: str) -> list:
        scan = self.get(scan_id, owner_id)
        return self.session.query(scan.findings).all() if scan else []

    def _business_id_for_website(self, owner_id: str, website_id: str) -> str | None:
        website = self.session.query(Website).join(Website.business).filter(Website.id == website_id, Website.business.has(owner_id=owner_id)).one_or_none()
        return website.business_id if website else None

    def _execute_in_background(self, scan_id: str) -> None:
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter_by(id=scan_id).one_or_none()
            if scan is None:
                return
            try:
                ScannerEngine(db).run(scan)
            finally:
                try:
                    AlertService(db).evaluate_scan_result(scan)
                except Exception:
                    # Alerting must never change the authoritative scan result.
                    logger.exception('Unable to evaluate alerts for scan %s', scan_id)
        finally:
            db.close()
