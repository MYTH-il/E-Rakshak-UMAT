from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=8, max_length=1024)
    roles: list[str] = Field(min_length=1)
    enabled: bool = True


class UserUpdateRequest(BaseModel):
    username: str | None = Field(default=None, min_length=1, max_length=128)
    password: str | None = Field(default=None, min_length=8, max_length=1024)
    roles: list[str] | None = Field(default=None, min_length=1)
    enabled: bool | None = None


class AdminUserResponse(BaseModel):
    id: UUID
    username: str
    roles: list[str]
    enabled: bool
    active_sessions: int
    created_at: datetime
    updated_at: datetime


class UserListResponse(BaseModel):
    items: list[AdminUserResponse]
    roles: list[str]


class SessionRevocationResponse(BaseModel):
    sessions_revoked: int
