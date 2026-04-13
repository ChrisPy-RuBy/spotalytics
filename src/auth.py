# auth.py
import httpx
from functools import lru_cache
from fastapi import Depends, HTTPException, Request, status
from jose import jwt, JWTError

CLERK_JWKS_URL = "https://unique-serval-83.clerk.accounts.dev/.well-known/jwks.json"
CLERK_ISSUER = "https://unique-serval-83.clerk.accounts.dev"

@lru_cache(maxsize=1)
def get_jwks():
    return httpx.get(CLERK_JWKS_URL).json()

async def get_current_user(request: Request) -> dict:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")

    token = auth_header.split(" ", 1)[1]
    try:
        headers = jwt.get_unverified_header(token)
        jwks = get_jwks()
        key = next((k for k in jwks["keys"] if k["kid"] == headers["kid"]), None)
        if key is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown signing key")

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=CLERK_ISSUER,
            options={"verify_aud": False},  # Clerk doesn't set aud by default
        )
    except JWTError as e:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {e}")

    return {"user_id": payload["sub"], "claims": payload}