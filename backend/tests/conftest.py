import pytest
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

# Set testing environment variables before importing app
os.environ["DEBUG"] = "False"
os.environ.setdefault("MYSQL_DATABASE_URL", "sqlite:///:memory:")
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-cyberscribe-testing-12345"
os.environ["GOOGLE_API_KEY"] = "fake-test-key-for-unit-testing"
os.environ["model_name"] = "gemini-1.5-flash"

from app.core.database import Base, get_db
from app.core.security import get_password_hash, create_access_token
from app import models
from main import app

from unittest.mock import patch, MagicMock

# Use SQLite in-memory database for fast, isolated test execution
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def mock_soar_delivery():
    """Mock all SOAR/webhook network delivery across pytest suite so external requests are never attempted."""
    with patch("app.agents.mitigation.requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json.return_value = {
            "status": "RECEIVED",
            "delivery_id": "mock-test-deliv",
            "message": "Mocked SOAR webhook receipt"
        }
        mock_resp.text = '{"status":"RECEIVED"}'
        mock_post.return_value = mock_resp
        yield mock_post


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_tenant(db):
    tenant = models.Tenant(
        company_name="Acme Cyber Defense Corp",
        tech_stack="FastAPI:0.110, Docker@24.x, PostgreSQL:15, Nginx:1.24",
        webhook_url="https://mock-soar-webhook.acme.local/containment",
        auth_token="ACME_SEC_TOKEN_998877"
    )
    db.add(tenant)
    db.commit()
    db.refresh(tenant)
    return tenant


@pytest.fixture
def sample_user(db, sample_tenant):
    user = models.User(
        email="analyst@acme.local",
        password_hash=get_password_hash("SecretPass123!"),
        role="tenant_admin",
        tenant_id=sample_tenant.id
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def sample_admin(db):
    admin = models.Admin(
        email="admin@cyberscribe.local",
        password_hash=get_password_hash("SuperAdminPass123!"),
        role="super_admin"
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    return admin


@pytest.fixture
def user_auth_token(sample_user):
    return create_access_token(data={
        "sub": sample_user.email,
        "role": sample_user.role,
        "tenant_id": sample_user.tenant_id
    })


@pytest.fixture
def admin_auth_token(sample_admin):
    return create_access_token(data={
        "sub": sample_admin.email,
        "role": "super_admin",
        "admin_id": sample_admin.id
    })


@pytest.fixture
def sample_threat_report(db):
    report = models.ThreatReport(
        title="FastAPI Request Smuggling Vulnerability",
        summary="A critical vulnerability in FastAPI endpoints allows remote attackers to bypass security filters.",
        severity="critical",
        cve_id="CVE-2026-9999",
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
        stix_bundle={
            "type": "bundle",
            "id": "bundle--cve-2026-9999",
            "spec_version": "2.1",
            "objects": [
                {
                    "type": "vulnerability",
                    "id": "vulnerability--cve-2026-9999",
                    "name": "FastAPI Request Smuggling",
                    "description": "Critical request smuggling flaw"
                }
            ]
        }
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report
