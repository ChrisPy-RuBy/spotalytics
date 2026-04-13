"""Tests for the file upload and extraction flow."""

import io
import json
import zipfile

import pytest
from starlette.testclient import TestClient

from main import app, app_state


@pytest.fixture(autouse=True)
def reset_app_state():
    """Ensure app state is clean before and after each test."""
    app_state.reset()
    yield
    app_state.reset()


def _make_zip(files: dict[str, bytes]) -> bytes:
    """Build an in-memory zip archive from a dict of {filename: content}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


MINIMAL_PLAYLIST = json.dumps(
    {"playlists": [{"name": "Test", "lastModifiedDate": "2024-01-01", "items": []}]}
).encode()


@pytest.fixture
def valid_zip() -> bytes:
    """A minimal valid Spotify export zip."""
    return _make_zip({"Playlist1.json.json": MINIMAL_PLAYLIST})


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app, follow_redirects=False)


class TestUploadEndpoint:
    """Tests for POST /api/upload."""

    def test_upload_valid_zip(self, client, valid_zip):
        """Uploading a valid zip should load data and redirect to /."""
        resp = client.post(
            "/api/upload",
            files={"file": ("export.zip", valid_zip, "application/zip")},
        )

        assert resp.status_code == 303
        assert resp.headers["location"] == "/"
        assert app_state.is_loaded

    def test_upload_not_a_zip(self, client):
        """Uploading a non-zip file should return 400."""
        resp = client.post(
            "/api/upload",
            files={"file": ("bad.zip", b"not a zip file", "application/zip")},
        )

        assert resp.status_code == 400
        assert "not a valid zip" in resp.json()["error"]
        assert not app_state.is_loaded

    def test_upload_missing_playlist_file(self, client):
        """A zip without Playlist1.json.json should return 400."""
        zip_bytes = _make_zip({"SomeOtherFile.json": b"{}"})

        resp = client.post(
            "/api/upload",
            files={"file": ("export.zip", zip_bytes, "application/zip")},
        )

        assert resp.status_code == 400
        assert "Playlist1.json.json" in resp.json()["error"]
        assert not app_state.is_loaded

    def test_upload_path_traversal(self, client):
        """A zip with path traversal entries should be rejected."""
        zip_bytes = _make_zip(
            {
                "../evil.txt": b"gotcha",
                "Playlist1.json.json": MINIMAL_PLAYLIST,
            }
        )

        resp = client.post(
            "/api/upload",
            files={"file": ("export.zip", zip_bytes, "application/zip")},
        )

        assert resp.status_code == 400
        assert "unsafe path" in resp.json()["error"]
        assert not app_state.is_loaded

    def test_upload_nested_zip(self, client):
        """A zip with data files inside a subdirectory should work."""
        zip_bytes = _make_zip({"my_spotify_data/Playlist1.json.json": MINIMAL_PLAYLIST})

        resp = client.post(
            "/api/upload",
            files={"file": ("export.zip", zip_bytes, "application/zip")},
        )

        assert resp.status_code == 303
        assert app_state.is_loaded
        # DataLoader should point at the subdirectory, not the extraction root
        assert app_state.loader.data_directory.name == "my_spotify_data"

    def test_upload_replaces_previous_data(self, client, valid_zip):
        """Uploading a second time should replace the previous dataset."""
        client.post(
            "/api/upload",
            files={"file": ("first.zip", valid_zip, "application/zip")},
        )
        first_dir = app_state._temp_dir

        client.post(
            "/api/upload",
            files={"file": ("second.zip", valid_zip, "application/zip")},
        )

        assert app_state.is_loaded
        # The first temp dir should have been cleaned up
        assert not first_dir.exists()


class TestDataGating:
    """Tests that routes require uploaded data."""

    def test_api_returns_403_without_upload(self, client):
        """API endpoints should return 403 when no data is loaded."""
        resp = client.get("/api/playlists/")

        assert resp.status_code == 403
        assert "No data loaded" in resp.json()["error"]

    def test_pages_redirect_to_upload_without_data(self, client):
        """Page routes should redirect to /upload when no data is loaded."""
        for path in ("/", "/playlists", "/tracks", "/analytics"):
            resp = client.get(path)
            assert resp.status_code == 307, f"{path} should redirect"
            assert resp.headers["location"] == "/upload"

    def test_upload_page_accessible_without_data(self, client):
        """The upload page itself should always be accessible."""
        resp = client.get("/upload")
        assert resp.status_code == 200
        assert "Upload Your Spotify Data" in resp.text

    def test_health_accessible_without_data(self, client):
        """The health endpoint should not be gated."""
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_no_redirect_after_upload(self, client, valid_zip):
        """Pages should render normally after data is uploaded."""
        client.post(
            "/api/upload",
            files={"file": ("export.zip", valid_zip, "application/zip")},
        )

        resp = client.get("/")
        assert resp.status_code == 200
        assert "Dashboard" in resp.text


class TestResetEndpoint:
    """Tests for POST /api/reset."""

    def test_reset_clears_data_and_redirects(self, client, valid_zip):
        """Resetting should clear state and redirect to /upload."""
        client.post(
            "/api/upload",
            files={"file": ("export.zip", valid_zip, "application/zip")},
        )
        assert app_state.is_loaded

        resp = client.post("/api/reset")

        assert resp.status_code == 303
        assert resp.headers["location"] == "/upload"
        assert not app_state.is_loaded

    def test_reset_cleans_up_temp_dir(self, client, valid_zip):
        """Resetting should remove the temporary extraction directory."""
        client.post(
            "/api/upload",
            files={"file": ("export.zip", valid_zip, "application/zip")},
        )
        temp_dir = app_state._temp_dir
        assert temp_dir.exists()

        client.post("/api/reset")

        assert not temp_dir.exists()

    def test_reset_when_no_data_loaded(self, client):
        """Resetting with no data loaded should still redirect cleanly."""
        resp = client.post("/api/reset")

        assert resp.status_code == 303
        assert resp.headers["location"] == "/upload"

    def test_nav_shows_reset_button_when_data_loaded(self, client, valid_zip):
        """The nav bar should show a reset button when data is loaded."""
        client.post(
            "/api/upload",
            files={"file": ("export.zip", valid_zip, "application/zip")},
        )

        resp = client.get("/")
        assert "Reset Data" in resp.text

    def test_upload_page_hides_reset_button(self, client):
        """The upload page should not show the reset button."""
        resp = client.get("/upload")
        assert "Reset Data" not in resp.text


class TestLifespanCleanup:
    """Tests that server shutdown cleans up temporary data."""

    def test_shutdown_cleans_up_temp_dir(self, valid_zip):
        """Exiting the TestClient context should trigger lifespan cleanup."""
        with TestClient(app) as client:
            client.post(
                "/api/upload",
                files={"file": ("export.zip", valid_zip, "application/zip")},
            )
            temp_dir = app_state._temp_dir
            assert temp_dir.exists()

        # After the context manager exits, lifespan shutdown runs
        assert not temp_dir.exists()
        assert not app_state.is_loaded
