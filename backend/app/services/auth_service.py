from __future__ import annotations

from datetime import datetime, timezone

from app.core.errors import AuthenticationFailedError, ResourceConflictError, ValidationError
from app.core.security import create_access_token, hash_password, normalize_email, verify_password
from app.models.entities import User
from app.repositories.user_repository import UserRepository


class AuthService:
    def __init__(self, session) -> None:
        self.session = session
        self.user_repo = UserRepository(session)

    def register(self, email: str, password: str, full_name: str) -> User:
        normalized_email = normalize_email(email)
        if not normalized_email or '@' not in normalized_email:
            raise ValidationError('Please provide a valid email address.')
        if len(password) < 12:
            raise ValidationError('Password must be at least 12 characters long.')
        clean_name = full_name.strip()
        if not clean_name:
            raise ValidationError('Full name is required.')

        if self.user_repo.get_by_email(normalized_email):
            raise ResourceConflictError('An account with this email already exists.')

        user = User(
            email=normalized_email,
            password_hash=hash_password(password),
            full_name=clean_name,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        self.user_repo.add(user)
        self.user_repo.commit()
        self.user_repo.refresh(user)
        return user

    def login(self, email: str, password: str) -> tuple[User, str]:
        normalized_email = normalize_email(email)
        user = self.user_repo.get_by_email(normalized_email)
        if user is None or not verify_password(password, user.password_hash):
            raise AuthenticationFailedError('Invalid email or password.')
        if not user.is_active:
            raise AuthenticationFailedError('This account is inactive.')

        user.last_login_at = datetime.now(timezone.utc)
        self.user_repo.commit()
        token = create_access_token(user.id)
        return user, token

    def get_current_user(self, user_id: str) -> User:
        user = self.user_repo.get_by_id(user_id)
        if user is None:
            raise AuthenticationFailedError('Invalid authentication credentials.')
        if not user.is_active:
            raise AuthenticationFailedError('This account is inactive.')
        return user
