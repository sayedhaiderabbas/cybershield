from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import User
from app.repositories.base import BaseRepository


class UserRepository(BaseRepository):
    model = User

    def __init__(self, session: Session) -> None:
        super().__init__(session)

    def get_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email.lower())
        return self.session.execute(stmt).scalar_one_or_none()
