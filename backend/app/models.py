from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base


def now():
    return datetime.now(timezone.utc)

# - sources: Almacena las fuentes de logs externas (agentes SSH, Nginx) y sus API keys hasheadas para autenticación.
class Source(Base):
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    type: Mapped[str] = mapped_column(String(20))
    api_key_hash: Mapped[str] = mapped_column(String(128))
    active: Mapped[bool] = mapped_column(Boolean, default=True)

# - events: Guarda cada evento de seguridad normalizado recibido de las fuentes, junto con sus metadatos, IPs y log original.
class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    source: Mapped[str] = mapped_column(String(20))
    event_type: Mapped[str] = mapped_column(String(30))
    src_ip: Mapped[str] = mapped_column(String(45))
    username: Mapped[str | None] = mapped_column(String(100))
    status: Mapped[str | None] = mapped_column(String(10))
    path: Mapped[str | None] = mapped_column(Text)
    http_status: Mapped[int | None]
    raw_log: Mapped[str] = mapped_column(Text)

    __table_args__ = (Index("ix_events_ip_time", "src_ip", "timestamp"),)

# - rules: Define las reglas de detección de amenazas (umbrales de intentos, ventanas de tiempo, severidad y código MITRE ATT&CK).
class Rule(Base):
    __tablename__ = "rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True)
    description: Mapped[str] = mapped_column(Text)
    threshold: Mapped[int]
    window_seconds: Mapped[int]
    severity: Mapped[str] = mapped_column(String(10))
    mitre: Mapped[str | None] = mapped_column(String(20))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

# - alerts: Almacena las alertas de seguridad generadas cuando el motor detecta un comportamiento anómalo o sospechoso.
class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    rule: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(10))
    src_ip: Mapped[str] = mapped_column(String(45))
    mitre: Mapped[str | None] = mapped_column(String(20))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="open")
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

# - users: Gestiona las cuentas y contraseñas (hasheadas) de los usuarios autorizados para iniciar sesión en el dashboard.
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
