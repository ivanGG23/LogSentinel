import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class LoginIn(BaseModel):
    username: str = Field(max_length=50)
    password: str = Field(max_length=200)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    rule: str
    severity: str
    src_ip: str
    mitre: str | None
    description: str
    status: str
    event_time: datetime
    created_at: datetime


class AlertUpdate(BaseModel):
    status: Literal["open", "reviewed", "false_positive"]
