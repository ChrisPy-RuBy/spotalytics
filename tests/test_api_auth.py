"""Integration tests verifying which routes require authentication."""

import pytest
from starlette.testclient import TestClient

from main import app, app_state
from src.auth import verify_session_cookie


@pytest.fixture(autouse=True)
def reset_app_state():
    app_state.reset()
    yield
    app_state.reset()


@pytest.fixture
def client():
    return TestClient(app, follow_redirects=False)


class TestProtectedRoutes:
    """API routes with Depends(verify_session_cookie) must return 401 when unauthenticated."""

    PROTECTED = [
        ("GET", "/api/playlists/"),
        ("GET", "/api/tracks/"),
        ("GET", "/api/analytics/top-tracks-by-playlist"),
        ("GET", "/api/analytics/top-tracks-by-plays"),
        ("GET", "/api/analytics/top-artists"),
        ("GET", "/api/analytics/overview"),
        ("GET", "/api/analytics/listening-time-stats"),
        ("POST", "/api/upload"),
        ("POST", "/api/reset"),
    ]

    @pytest.mark.parametrize("method,path", PROTECTED)
    def test_returns_401_without_cookie(self, client, method, path):
        resp = client.request(method, path)
        assert resp.status_code == 401, f"{method} {path} should require auth"


class TestPublicRoutes:
    """These routes must be reachable without authentication."""

    def test_health_is_public(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_sign_in_page_is_public(self, client):
        resp = client.get("/sign-in")
        assert resp.status_code == 200

    def test_static_files_are_public(self, client):
        # Static files are mounted at /static — a missing file returns 404, not 401
        resp = client.get("/static/nonexistent.txt")
        assert resp.status_code == 404


class TestSignOut:
    """Tests for POST /api/sign-out."""

    def test_sign_out_redirects_to_sign_in(self, client):
        resp = client.post("/api/sign-out")
        assert resp.status_code == 303
        assert resp.headers["location"] == "/sign-in"

    def test_sign_out_clears_session_cookie(self, client):
        resp = client.post("/api/sign-out")
        # Starlette sets a cookie with empty value and max-age=0 to delete it
        deleted = resp.cookies.get("__session")
        assert deleted is None or deleted == ""

    def test_sign_out_is_public(self, client):
        """Sign-out should work even without a valid session cookie."""
        resp = client.post("/api/sign-out")
        assert resp.status_code == 303


class TestAuthenticatedAccess:
    """Routes behave correctly once the auth dependency is satisfied."""

    @pytest.fixture(autouse=True)
    def mock_auth(self):
        app.dependency_overrides[verify_session_cookie] = lambda: {"sub": "test-user-id"}
        yield
        app.dependency_overrides.pop(verify_session_cookie, None)

    def test_api_playlists_returns_403_without_data(self, client):
        """Authenticated but no data uploaded → data gating returns 403."""
        resp = client.get("/api/playlists/")
        assert resp.status_code == 403
        assert "No data loaded" in resp.json()["error"]

    def test_api_analytics_returns_403_without_data(self, client):
        resp = client.get("/api/analytics/overview")
        assert resp.status_code == 403
