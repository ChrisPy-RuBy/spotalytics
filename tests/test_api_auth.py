"""Integration tests verifying which routes require authentication."""

import io
import json
import zipfile

import pytest
from starlette.testclient import TestClient

from main import app, app_state
from src.auth import verify_session_cookie


@pytest.fixture
def valid_zip() -> bytes:
    buf = io.BytesIO()
    payload = json.dumps(
        {"playlists": [{"name": "Test", "lastModifiedDate": "2024-01-01", "items": []}]}
    ).encode()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Playlist1.json.json", payload)
    return buf.getvalue()


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


@pytest.mark.usefixtures("mock_auth")
class TestSignOut:
    """Tests for GET /api/sign-out."""

    def test_sign_out_redirects_to_sign_in(self, client):
        resp = client.get("/api/sign-out")
        assert resp.status_code == 303
        assert resp.headers["location"] == "/sign-in"

    def test_sign_out_is_public(self, client):
        """Sign-out should work even without a valid session cookie."""
        resp = client.get("/api/sign-out")
        assert resp.status_code == 303

    def test_sign_out_resets_app_data(self, client, valid_zip):
        """Sign-out should clear any loaded Spotify data."""
        client.post(
            "/api/upload",
            files={"file": ("export.zip", valid_zip, "application/zip")},
        )
        assert app_state.is_loaded

        client.get("/api/sign-out")
        assert not app_state.is_loaded


class TestUnauthenticatedPageRoutes:
    """Unauthenticated browser requests to page routes should end up at /sign-in."""

    def test_upload_redirects_to_sign_in(self, client):
        """/upload has auth dep directly — 401 becomes a redirect to /sign-in."""
        resp = client.get("/upload")
        assert resp.status_code == 307
        assert resp.headers["location"] == "/sign-in"

    @pytest.mark.parametrize("path", ["/", "/playlists", "/tracks", "/analytics"])
    def test_data_gated_pages_redirect_to_upload(self, client, path):
        """With no data loaded, require_data redirects to /upload first.
        The browser would then follow that to /sign-in, but TestClient sees only the first hop."""
        resp = client.get(path)
        assert resp.status_code == 307
        assert resp.headers["location"] == "/upload"

    def test_api_401_returns_json_not_redirect(self, client):
        """API routes should still return JSON 401, not redirect."""
        resp = client.get("/api/playlists/")
        assert resp.status_code == 401
        assert resp.headers["content-type"].startswith("application/json")


class TestAuthenticatedAccess:
    """Routes behave correctly once the auth dependency is satisfied."""

    @pytest.fixture(autouse=True)
    def mock_auth(self):
        app.dependency_overrides[verify_session_cookie] = lambda: {
            "sub": "test-user-id"
        }
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
