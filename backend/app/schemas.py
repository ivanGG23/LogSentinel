import ipaddress
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class EventIn(BaseModel):
    timestamp: datetime
    event_type: str = Field(pattern="^(login|http_request)$")
    src_ip: str
    username: str | None = Field(default=None, max_length=100)
    status: str | None = Field(default=None, pattern="^(success|fail)$")
    path: str | None = Field(default=None, max_length=2000)
    http_status: int | None = Field(default=None, ge=100, le=599)
    raw_log: str = Field(max_length=4000)

    @field_validator("src_ip")
    @classmethod
    def valid_ip(cls, v: str) -> str:
        ipaddress.ip_address(v)  # lanza error si no es una IP válida
        return v
