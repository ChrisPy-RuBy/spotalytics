"""Unit tests for verify_session_cookie in src/auth.py."""

import asyncio
import base64
import time

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from jose import jwt
from starlette.requests import Request
from unittest.mock import AsyncMock, patch

import src.auth as auth_module
from src.auth import CLERK_ISSUER, verify_session_cookie

# ---------------------------------------------------------------------------
# Test RSA key pair — generated once for the whole module
# ---------------------------------------------------------------------------

_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
_pub_numbers = _private_key.public_key().public_numbers()
_private_pem = _private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
).decode()


def _b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


TEST_JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "test-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": _b64url(_pub_numbers.n),
            "e": _b64url(_pub_numbers.e),
        }
    ]
}


def _make_token(overrides: dict = None, kid: str = "test-key-1") -> str:
    """Return a signed JWT using the test RSA key."""
    claims = {
        "sub": "user_test_123",
        "iss": CLERK_ISSUER,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }
    if overrides:
        claims.update(overrides)
    return jwt.encode(claims, _private_pem, algorithm="RS256", headers={"kid": kid})


def _make_request(cookies: dict = None) -> Request:
    cookie_str = "; ".join(f"{k}={v}" for k, v in (cookies or {}).items())
    headers = [(b"cookie", cookie_str.encode())] if cookie_str else []
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": headers,
    }
    return Request(scope)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_jwks_cache():
    """Clear the in-memory JWKS cache before each test."""
    auth_module._jwks_cache = None
    yield
    auth_module._jwks_cache = None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestVerifySessionCookie:
    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    def test_no_cookie_raises_401(self):
        request = _make_request()
        with pytest.raises(HTTPException) as exc:
            self._run(verify_session_cookie(request))
        assert exc.value.status_code == 401

    def test_garbage_token_raises_401(self):
        request = _make_request({"__session": "not.a.jwt"})
        with patch(
            "src.auth._get_jwks", new=AsyncMock(return_value=TEST_JWKS)
        ):
            with pytest.raises(HTTPException) as exc:
                self._run(verify_session_cookie(request))
        assert exc.value.status_code == 401

    def test_expired_token_raises_401(self):
        token = _make_token({"exp": int(time.time()) - 10})
        request = _make_request({"__session": token})
        with patch(
            "src.auth._get_jwks", new=AsyncMock(return_value=TEST_JWKS)
        ):
            with pytest.raises(HTTPException) as exc:
                self._run(verify_session_cookie(request))
        assert exc.value.status_code == 401

    def test_wrong_issuer_raises_401(self):
        token = _make_token({"iss": "https://evil.example.com"})
        request = _make_request({"__session": token})
        with patch(
            "src.auth._get_jwks", new=AsyncMock(return_value=TEST_JWKS)
        ):
            with pytest.raises(HTTPException) as exc:
                self._run(verify_session_cookie(request))
        assert exc.value.status_code == 401

    def test_valid_token_returns_claims(self):
        token = _make_token()
        request = _make_request({"__session": token})
        with patch(
            "src.auth._get_jwks", new=AsyncMock(return_value=TEST_JWKS)
        ):
            claims = self._run(verify_session_cookie(request))
        assert claims["sub"] == "user_test_123"
        assert claims["iss"] == CLERK_ISSUER

    def test_key_rotation_retries_with_fresh_jwks(self):
        """If the first JWKS fetch returns stale keys, a retry with fresh keys should succeed."""
        token = _make_token()
        request = _make_request({"__session": token})

        # First call returns an empty key set (simulating stale cache),
        # second call (force_refresh=True) returns the correct keys.
        stale_jwks = {"keys": []}

        async def _fake_get_jwks(force_refresh=False):
            return TEST_JWKS if force_refresh else stale_jwks

        with patch("src.auth._get_jwks", side_effect=_fake_get_jwks):
            claims = self._run(verify_session_cookie(request))

        assert claims["sub"] == "user_test_123"

    def test_key_rotation_still_raises_if_fresh_jwks_also_fails(self):
        """If both JWKS fetches fail to verify, 401 is raised."""
        token = _make_token()
        request = _make_request({"__session": token})
        empty_jwks = {"keys": []}

        with patch(
            "src.auth._get_jwks", new=AsyncMock(return_value=empty_jwks)
        ):
            with pytest.raises(HTTPException) as exc:
                self._run(verify_session_cookie(request))
        assert exc.value.status_code == 401
