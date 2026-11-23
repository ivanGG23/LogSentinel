import os
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .database import Base, SessionLocal, engine, get_db
from .models import Alert, Event, Source
from .ratelimit import RateLimitMiddleware, client_ip, login_ip_limiter, login_user_limiter
from .rules_engine import evaluate_event, seed_rules
from .schemas import AlertOut, AlertUpdate, EventIn, LoginIn, StatsOut, TokenOut
from .security import (
    authenticate,
    create_access_token,
    get_current_user,
    get_source,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        seed_rules(db)
    yield


app = FastAPI(title="LogSentinel", lifespan=lifespan)


# Límite general de peticiones. Se agrega ANTES que CORS para que CORS quede como capa
# externa y las respuestas 429 también lleven sus cabeceras.
app.add_middleware(RateLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get(
        "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(","),
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


# ---------- Eventos (agentes, con API key) ----------

@app.post("/events", status_code=201)
def create_event(
    event: EventIn,
    source: Source = Depends(get_source),
    db: Session = Depends(get_db),
):
    row = Event(**event.model_dump(), source_id=source.id, source=source.type)
    db.add(row)
    db.commit()
    evaluate_event(db, row)
    return {"id": row.id}


# ---------- Autenticación (dashboard) ----------

@app.post("/auth/login", response_model=TokenOut)
def login(data: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    user_key = data.username.strip().lower()
    # El límite se revisa ANTES de verificar la contraseña (Argon2 es costoso)
    wait = max(login_ip_limiter.retry_after(ip), login_user_limiter.retry_after(user_key))
    if wait:
        raise HTTPException(
            status_code=429,
            detail="Demasiados intentos fallidos. Intenta más tarde.",
            headers={"Retry-After": str(wait)},
        )
    user = authenticate(db, data.username, data.password)
    if user is None:
        login_ip_limiter.add(ip)
        login_user_limiter.add(user_key)
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    login_user_limiter.clear(user_key)
    return TokenOut(access_token=create_access_token(user.username))


# ---------- Alertas (dashboard, con JWT) ----------

@app.get("/alerts", response_model=list[AlertOut],
         dependencies=[Depends(get_current_user)])
def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    rule: str | None = None,
    src_ip: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = select(Alert).order_by(Alert.event_time.desc(), Alert.id.desc())
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    if rule:
        q = q.where(Alert.rule == rule)
    if src_ip:
        q = q.where(Alert.src_ip == src_ip)
    return db.scalars(q.limit(limit).offset(offset)).all()


@app.patch("/alerts/{alert_id}", response_model=AlertOut,
           dependencies=[Depends(get_current_user)])
def update_alert(alert_id: int, data: AlertUpdate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alerta no encontrada")
    alert.status = data.status
    db.commit()
    db.refresh(alert)
    return alert


# ---------- Estadísticas (dashboard, con JWT) ----------

@app.get("/stats", response_model=StatsOut, dependencies=[Depends(get_current_user)])
def stats(db: Session = Depends(get_db)):
    rows = db.execute(select(Event.source, func.count()).group_by(Event.source)).all()
    return StatsOut(events_by_source={src: n for src, n in rows})
