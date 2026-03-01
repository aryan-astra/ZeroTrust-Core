"""
ZeroTrust - JWT Authentication Module
Handles token creation, validation, and role-based access control.
"""

import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Bearer token scheme
security = HTTPBearer()

# In-memory user store (replace with DB in production)
USERS_DB = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("admin123"),
        "role": "admin",
        "disabled": False,
    },
    "analyst": {
        "username": "analyst",
        "hashed_password": pwd_context.hash("analyst123"),
        "role": "analyst",
        "disabled": False,
    },
}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Authenticate against user store."""
    user = USERS_DB.get(username)
    if not user or user.get("disabled"):
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.JWT_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token: no subject")
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """FastAPI dependency: extract user from Bearer token."""
    payload = decode_token(credentials.credentials)
    username = payload.get("sub")
    user = USERS_DB.get(username)
    if user is None or user.get("disabled"):
        raise HTTPException(status_code=401, detail="User not found or disabled")
    return user


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """FastAPI dependency: require admin role."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def require_analyst(user: dict = Depends(get_current_user)) -> dict:
    """FastAPI dependency: require analyst or admin role."""
    if user.get("role") not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst access required")
    return user
