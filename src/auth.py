# auth.py
import httpx
from fastapi import HTTPException, Request
from jose import JWTError, jwt

CLERK_JWKS_URL = "https://unique-serval-83.clerk.accounts.dev/.well-known/jwks.json"
CLERK_ISSUER = "https://unique-serval-83.clerk.accounts.dev"

_jwks_cache: dict | None = None


async def _get_jwks(force_refresh: bool = False) -> dict:
    global _jwks_cache
    if _jwks_cache is None or force_refresh:
        async with httpx.AsyncClient() as client:
            r = await client.get(CLERK_JWKS_URL)
            r.raise_for_status()
            _jwks_cache = r.json()
    return _jwks_cache


async def verify_session_cookie(request: Request) -> dict:
    """
    Reads the __session cookie and verifies it.
    Returns the JWT claims dict if valid.
    Raises HTTPException(401) if missing or invalid.
    """
    token = request.cookies.get("__session")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        jwks = await _get_jwks()
        claims = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            issuer=CLERK_ISSUER,
            options={"verify_aud": False},
        )
        return claims
    except JWTError:
        # Try once more with a fresh JWKS in case keys were rotated
        try:
            jwks = await _get_jwks(force_refresh=True)
            claims = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                issuer=CLERK_ISSUER,
                options={"verify_aud": False},
            )
            return claims
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid session")
