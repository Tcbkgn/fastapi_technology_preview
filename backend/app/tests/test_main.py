from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app import scopes
from backend.app.main import app
from backend.app.utils import get_db, get_pwd_context
from backend.db.schemas import Base, User

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        database = TestingSessionLocal()
        yield database
    finally:
        database.close()

app.dependency_overrides[get_db] = override_get_db

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)

pwd_context = get_pwd_context()
db = next(override_get_db())

user = User(username="admin", password=pwd_context.hash("pass"), active=True, admin=True)
user_inactive = User(username="user1", password=pwd_context.hash("pass"), active=False, admin=False)
user_active = User(username="user2", password=pwd_context.hash("pass"), active=False, admin=False)
db.add_all([user, user_inactive, user_active])
db.commit()

client = TestClient(app)

class TestAuth:
    def test_login_correct(self):
        response = client.post(
            "/api/auth/token",
            {
                "grant_type": "password",
                "username": "admin",
                "password": "pass",
                "scope": "+".join([scopes.ACTIVE, scopes.LOGGED_IN, scopes.ADMIN])
            }
        )
        response_data = response.json()
        assert response.status_code== 200
        assert "access_token" in response_data
        assert "token_type" in response_data
        assert response_data["token_type"] == "bearer"

    def test_username_non_existent(self):
        response = client.post(
            "/api/auth/token",
            {
                "grant_type": "password",
                "username": "nonex",
                "password": "pass",
                "scope": "+".join([scopes.ACTIVE, scopes.LOGGED_IN, scopes.ADMIN])
            }
        )
        assert response.status_code == 400

    def test_invalid_data(self):
        response = client.post(
            "/api/auth/token",
            {
                "grant_type": "invalid_grant_type",
                "username": "nonex",
                "password": "pass",
                "scope": "+".join([scopes.ACTIVE, scopes.LOGGED_IN, scopes.ADMIN])
            }
        )
        assert response.status_code == 422
