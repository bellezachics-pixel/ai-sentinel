"""
Configuracion de pytest para AI-Sentinel backend.

Debe ejecutarse asi (desde el directorio backend/):
    .venv/bin/python -m pytest tests/ -q

El entorno (DATA_DIR temporal + SECRET_KEY fijo) se configura ANTES de
importar la app, para que los stores JSON nunca toquen datos reales.
"""
import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# --- Environment MUST be set before importing the app ---
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="sentinel-test-data-")
os.environ["SECRET_KEY"] = "test-secret-key-pytest-only-0123456789abcdef"
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("REQUIRE_AUTH_FOR_ANALYSIS", "false")
os.environ.pop("ADMIN_PASSWORD", None)  # keep the admin user out of tests

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.core import auth as auth_core  # noqa: E402
from app.core.security import rate_limit_store  # noqa: E402

AUTH_PREFIX = "/api/v1/auth"
API_PREFIX = "/api/v1"


@pytest.fixture(autouse=True)
def _reset_rate_limit_state():
    """Rate limiting / brute-force state is global and in-memory; isolate it."""
    rate_limit_store.requests.clear()
    rate_limit_store.blocked_ips.clear()
    rate_limit_store.failed_auth.clear()
    yield
    rate_limit_store.requests.clear()
    rate_limit_store.blocked_ips.clear()
    rate_limit_store.failed_auth.clear()


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def make_user(client, username: str | None = None, password: str = "Passw0rd!x") -> dict:
    """Register a fresh user and return its tokens/headers."""
    username = username or f"user_{uuid.uuid4().hex[:10]}"
    resp = client.post(
        f"{AUTH_PREFIX}/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
        },
    )
    assert resp.status_code == 200, resp.text
    tokens = resp.json()
    return {
        "username": username,
        "password": password,
        "access": tokens["access_token"],
        "refresh": tokens["refresh_token"],
        "headers": {"Authorization": f"Bearer {tokens['access_token']}"},
    }


@pytest.fixture()
def auth_client(client):
    """A TestClient plus a registered user's auth headers."""
    user = make_user(client)
    return client, user
