import os
import uuid
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ['DATABASE_URL'] = 'sqlite://'
os.environ['JWT_SECRET'] = 'a-very-long-jwt-secret-key-for-testing-1234567890'
os.environ['APP_ENV'] = 'test'
os.environ['ENABLE_LEGACY_USER_HEADER'] = 'true'

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.entities import User

engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)


def override_get_db() -> Generator:
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_database() -> Generator:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


@pytest.fixture()
def user_record() -> User:
    db = TestingSessionLocal()
    user = User(email=f'owner-{uuid.uuid4()}@example.com', password_hash='hashed-password', full_name='Owner User', is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    db.close()
    return user
