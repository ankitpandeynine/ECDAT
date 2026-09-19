"""
Tests for ECDAT Phase 5 (Authentication, RBAC) and Phase 6 (Project Management).
"""
import pytest
from engine.scan_store import ScanStore
from engine.auth import hash_password, verify_password, UserRole
from engine.projects import BusinessCriticality, DataSensitivity, EnvironmentType


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test_auth.sqlite3")
    return ScanStore(db_path)


def test_password_hashing():
    p = "SuperSecretPassword2026!"
    h, salt = hash_password(p)
    assert verify_password(p, h, salt) is True
    assert verify_password("WrongPassword", h, salt) is False


def test_default_admin_and_project_seeded(store):
    # Default admin must be seeded
    admin = store.auth.authenticate_user("admin@ecdat.local", "admin123")
    assert admin is not None
    assert admin["role"] == UserRole.OWNER.value

    # Default project must be seeded
    proj = store.projects.get_project("default")
    assert proj is not None
    assert proj["name"] == "Default Enterprise System"
    assert proj["environment"] == EnvironmentType.PRODUCTION.value
    assert proj["business_criticality"] == BusinessCriticality.CRITICAL.value
    assert proj["data_lifetime_years"] == 20.0


def test_user_registration_and_auth(store):
    # Register analyst
    user = store.auth.register_user("analyst@bank.com", "analystPass123", "Jane Doe", UserRole.SECURITY_ANALYST.value)
    assert user["email"] == "analyst@bank.com"
    assert user["role"] == UserRole.SECURITY_ANALYST.value
    assert user["token"] is not None

    # Validate session
    sess = store.auth.validate_session(user["token"])
    assert sess is not None
    assert sess["email"] == "analyst@bank.com"

    # Reject duplicate registration
    with pytest.raises(ValueError, match="already exists"):
        store.auth.register_user("analyst@bank.com", "anotherPass", "Duplicate Jane")

    # Logout
    store.auth.invalidate_session(user["token"])
    assert store.auth.validate_session(user["token"]) is None


def test_project_crud(store):
    p_data = {
        "id": "proj-banking-core",
        "name": "Global Payment Core",
        "description": "High-throughput financial ledger and payment switch",
        "organization": "Global Payments Corp",
        "environment": EnvironmentType.PRODUCTION.value,
        "business_criticality": BusinessCriticality.CRITICAL.value,
        "data_sensitivity": DataSensitivity.CLASSIFIED.value,
        "data_lifetime_years": 25.0,
        "migration_target_date": "2028-12-31",
        "tags": ["swift", "pqc-high-priority", "tier-1"]
    }
    created = store.projects.create_project(p_data, owner="ciso@payments.corp")
    assert created["id"] == "proj-banking-core"
    assert created["business_criticality"] == "Critical"
    assert created["data_sensitivity"] == "Classified"
    assert created["data_lifetime_years"] == 25.0
    assert "swift" in created["tags"]

    # Update project
    updated = store.projects.update_project("proj-banking-core", {"data_lifetime_years": 30.0})
    assert updated["data_lifetime_years"] == 30.0

    # Search project
    plist = store.projects.list_projects(search="payment")
    assert any(p["id"] == "proj-banking-core" for p in plist)

    # Delete project
    assert store.projects.delete_project("proj-banking-core") is True
    assert store.projects.get_project("proj-banking-core") is None


def test_audit_logging(store):
    store.auth.log_audit(action="KEY_ROTATION_ATTEMPT", user_id="user-test", project_id="default", details="Rotated RSA-2048 to ML-KEM-768")
    logs = store.auth.get_audit_logs(project_id="default")
    assert len(logs) > 0
    assert logs[0]["action"] == "KEY_ROTATION_ATTEMPT"
