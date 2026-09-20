from __future__ import annotations

from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.entities import Business, Website
from app.repositories.business_repository import BusinessRepository
from app.repositories.website_repository import WebsiteRepository
from app.schemas import WebsiteCreate, WebsiteUpdate
from app.services.base import ensure_entity
from app.utils.url import normalize_url


class WebsiteService:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.repo = WebsiteRepository(session)
        self.business_repo = BusinessRepository(session)

    def create(self, owner_id: str, payload: WebsiteCreate) -> Website:
        business = self.business_repo.get_for_owner(payload.business_id, owner_id)
        ensure_entity(business, 'Business not found or access denied.')
        normalized_url, hostname = normalize_url(payload.url)
        existing = self.repo.get_by_normalized_url(payload.business_id, normalized_url)
        if existing is not None:
            raise HTTPException(status_code=409, detail='Website already exists for this business.')
        website = Website(
            business_id=payload.business_id,
            name=payload.name.strip(),
            url=payload.url.strip(),
            normalized_url=normalized_url,
            hostname=hostname,
            status='pending',
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.repo.add(website)
        self.repo.commit()
        self.repo.refresh(website)
        return website

    def list(self, owner_id: str, page: int, page_size: int) -> tuple[list[Website], int]:
        businesses = self.business_repo.list_for_owner(owner_id)
        business_ids = [business.id for business in businesses]
        if not business_ids:
            return [], 0
        query = self.session.query(Website).filter(Website.business_id.in_(business_ids))
        total = query.count()
        items = query.order_by(Website.created_at.desc(), Website.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
        return items, total

    def get(self, website_id: str, owner_id: str) -> Website:
        website = self.session.query(Website).join(Business).filter(Website.id == website_id, Business.owner_id == owner_id).one_or_none()
        ensure_entity(website, 'Website not found.')
        return website

    def update(self, website_id: str, owner_id: str, payload: WebsiteUpdate) -> Website:
        website = self.get(website_id, owner_id)
        if payload.name is not None:
            website.name = payload.name.strip()
        if payload.url is not None:
            normalized, hostname = normalize_url(payload.url)
            website.url = payload.url.strip()
            website.normalized_url = normalized
            website.hostname = hostname
        if payload.status is not None:
            website.status = payload.status
        website.updated_at = datetime.utcnow()
        self.repo.commit()
        return website

    def delete(self, website_id: str, owner_id: str) -> None:
        website = self.get(website_id, owner_id)
        self.session.delete(website)
        self.repo.commit()
