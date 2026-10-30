from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import Base, SessionLocal, engine, get_db
from .models import Alert, Event, Source
from .rules_engine import evaluate_event, seed_rules
from .schemas import AlertOut, AlertUpdate, EventIn, LoginIn, TokenOut
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
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = authenticate(db, data.username, data.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
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
