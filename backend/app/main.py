from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session
from .database import Base, engine, get_db
from .models import Event, Source
from .schemas import EventIn
from .security import get_source


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    yield


app = FastAPI(title="LogSentinel", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/events", status_code=201)
def create_event(
    event: EventIn,
    source: Source = Depends(get_source),
    db: Session = Depends(get_db),
):
    row = Event(**event.model_dump(), source_id=source.id, source=source.type)
    db.add(row)
    db.commit()
    return {"id": row.id}
