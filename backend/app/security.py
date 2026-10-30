import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, Header, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import get_db
from .models import Source, User

# ---------- API keys (agentes y aplicaciones) ----------


def generate_api_key() -> str:
    return "ls_" + secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def get_source(
    x_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Source:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Falta la API key")
    source = db.scalar(
        select(Source).where(
            Source.api_key_hash == hash_api_key(x_api_key),
            Source.active.is_(True),
        )
    )
    if source is None:
        raise HTTPException(status_code=401, detail="API key inválida")
    return source


# ---------- Usuarios y JWT (dashboard) ----------

JWT_SECRET = os.environ.get("JWT_SECRET", "")
if len(JWT_SECRET) < 32:
    raise RuntimeError("JWT_SECRET no está definido o es demasiado corto (mínimo 32 caracteres)")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "30"))

_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash("contraseña-de-relleno")
_bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = db.scalar(select(User).where(User.username == username, User.active.is_(True)))
    # Siempre se verifica un hash, para que el tiempo no revele si el usuario existe
    ok = verify_password(password, user.password_hash if user else _DUMMY_HASH)
    return user if (user is not None and ok) else None


def create_access_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status_code=401,
        detail="No autenticado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if creds is None:
        raise unauthorized
    try:
        payload = jwt.decode(
            creds.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],          # algoritmo fijado explícitamente
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError:
        raise unauthorized
    user = db.scalar(
        select(User).where(User.username == payload["sub"], User.active.is_(True))
    )
    if user is None:
        raise unauthorized
    return user
