from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.entities import Business, User
from app.repositories.business_repository import BusinessRepository
from app.repositories.user_repository import UserRepository
from app.schemas import BusinessCreate, BusinessUpdate
from app.services.base import ensure_entity, ensure_ownership


@dataclass
class BusinessService:
    session: Session

    def __post_init__(self) -> None:
        self.repo = BusinessRepository(self.session)
        self.user_repo = UserRepository(self.session)

    def create(self, owner_id: str, payload: BusinessCreate) -> Business:
        owner = self.user_repo.get_by_id(owner_id)
        ensure_entity(owner, 'User not found.')
        business = Business(
            owner_id=owner_id,
            name=payload.name.strip(),
            industry=payload.industry.strip() if payload.industry else None,
            description=payload.description.strip() if payload.description else None,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        self.repo.add(business)
        self.repo.commit()
        self.repo.refresh(business)
        return business

    def list(self, owner_id: str, page: int, page_size: int) -> tuple[list[Business], int]:
        return self.repo.list_for_owner(owner_id, page, page_size), self.repo.count_for_owner(owner_id)

    def get(self, business_id: str, owner_id: str) -> Business:
        business = self.repo.get_for_owner(business_id, owner_id)
        ensure_entity(business, 'Business not found.')
        return business

    def update(self, business_id: str, owner_id: str, payload: BusinessUpdate) -> Business:
        business = self.get(business_id, owner_id)
        if payload.name is not None:
            business.name = payload.name.strip()
        if payload.industry is not None:
            business.industry = payload.industry.strip()
        if payload.description is not None:
            business.description = payload.description.strip()
        business.updated_at = datetime.utcnow()
        self.repo.commit()
        return business

    def delete(self, business_id: str, owner_id: str) -> None:
        business = self.get(business_id, owner_id)
        self.session.delete(business)
        self.repo.commit()
