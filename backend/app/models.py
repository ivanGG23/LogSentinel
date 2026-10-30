from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base


def now():
    return datetime.now(timezone.utc)


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    type: Mapped[str] = mapped_column(String(20))        # ssh | web | nginx
    api_key_hash: Mapped[str] = mapped_column(String(128))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    source: Mapped[str] = mapped_column(String(20))
    event_type: Mapped[str] = mapped_column(String(30))  # login | http_request
    src_ip: Mapped[str] = mapped_column(String(45))
    username: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str | None] = mapped_column(String(10))  # success | fail
    path: Mapped[str | None] = mapped_column(Text)          # solo eventos HTTP
    http_status: Mapped[int | None]                         # solo eventos HTTP
    raw_log: Mapped[str] = mapped_column(Text)

    __table_args__ = (Index("ix_events_ip_time", "src_ip", "timestamp"),)


class Rule(Base):
    __tablename__ = "rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True)
    description: Mapped[str] = mapped_column(Text)
    threshold: Mapped[int]
    window_seconds: Mapped[int]
    severity: Mapped[str] = mapped_column(String(10))    # low | medium | high | critical
    mitre: Mapped[str | None] = mapped_column(String(20))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(10))
    src_ip: Mapped[str] = mapped_column(String(45))
    mitre: Mapped[str | None] = mapped_column(String(20))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="open")  # open | reviewed | false_positive
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))  # hora del evento que la disparó
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
