import hashlib
import secrets
from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from .database import get_db
from .models import Source


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
