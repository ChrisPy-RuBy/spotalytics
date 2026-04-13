"""Shared fixtures for the test suite."""

import pytest

from main import app
from src.auth import verify_session_cookie


@pytest.fixture
def mock_auth():
    """Override Clerk session verification so tests don't need a real JWT."""
    app.dependency_overrides[verify_session_cookie] = lambda: {"sub": "test-user-id"}
    yield
    app.dependency_overrides.pop(verify_session_cookie, None)
