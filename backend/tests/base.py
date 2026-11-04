import os
import unittest
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Set testing environment variables
os.environ["DEBUG"] = "False"
os.environ.setdefault("MYSQL_DATABASE_URL", "sqlite:///:memory:")
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-cyberscribe-testing-12345"
os.environ["GOOGLE_API_KEY"] = "fake-test-key-for-unit-testing"
os.environ["model_name"] = "gemini-1.5-flash"

from app.core.database import Base, get_db
from app.core.security import get_password_hash, create_access_token
from app import models
from main import app

# In-memory SQLite for testing with StaticPool to keep single persistent in-memory db during test
engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class BaseTestCase(unittest.TestCase):
    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.db = TestingSessionLocal()
        
        def override_get_db():
            db = TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Seed sample tenant
        self.tenant = models.Tenant(
            company_name="Acme Cyber Defense Corp",
            tech_stack="FastAPI:0.110, Docker@24.x, PostgreSQL:15, Nginx:1.24",
            webhook_url="https://mock-soar-webhook.acme.local/containment",
            auth_token="ACME_SEC_TOKEN_998877"
        )
        self.db.add(self.tenant)
        self.db.commit()
        self.db.refresh(self.tenant)

        # Seed sample user
        self.user = models.User(
            email="analyst@acme.local",
            password_hash=get_password_hash("SecretPass123!"),
            role="tenant_admin",
            tenant_id=self.tenant.id
        )
        self.db.add(self.user)
        self.db.commit()
        self.db.refresh(self.user)

        # Seed sample admin
        self.admin = models.Admin(
            email="admin@cyberscribe.local",
            password_hash=get_password_hash("SuperAdminPass123!"),
            role="super_admin"
        )
        self.db.add(self.admin)
        self.db.commit()
        self.db.refresh(self.admin)

        # Auth tokens
        self.user_token = create_access_token(data={
            "sub": self.user.email,
            "role": self.user.role,
            "tenant_id": self.user.tenant_id
        })
        self.admin_token = create_access_token(data={
            "sub": self.admin.email,
            "role": "super_admin",
            "admin_id": self.admin.id
        })
        self.user_headers = {"Authorization": f"Bearer {self.user_token}"}
        self.admin_headers = {"Authorization": f"Bearer {self.admin_token}"}

        # Mock SOAR/webhook network delivery across all tests so external network requests are never attempted
        self.mock_soar_patcher = patch("app.agents.mitigation.requests.post")
        self.mock_soar_post = self.mock_soar_patcher.start()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "status": "RECEIVED",
            "delivery_id": "mock-test-deliv",
            "message": "Mocked SOAR webhook receipt"
        }
        mock_resp.text = '{"status":"RECEIVED"}'
        self.mock_soar_post.return_value = mock_resp

    def tearDown(self):
        if hasattr(self, "mock_soar_patcher"):
            self.mock_soar_patcher.stop()
        self.db.close()
        app.dependency_overrides.clear()
        with engine.connect() as conn:
            conn.execute(text("PRAGMA foreign_keys = OFF"))
            conn.commit()
        Base.metadata.drop_all(bind=engine)
