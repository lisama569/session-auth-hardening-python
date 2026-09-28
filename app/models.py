"""领域模型：角色、会话、令牌记录与请求/响应体。"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class Role(str, Enum):
    ADMIN = "admin"
    MEMBER = "member"


@dataclass(frozen=True)
class UserRecord:
    username: str
    password: str
    roles: tuple[str, ...]


@dataclass
class AccessRecord:
    jti: str
    session_id: str
    username: str
    expires_at: datetime
    revoked: bool = False


@dataclass
class RefreshRecord:
    jti: str
    session_id: str
    family_id: str
    expires_at: datetime
    state: str = "active"  # active | used | revoked
    rotated_at: datetime | None = None
    reuse_seen: bool = False
    replaced_by_jti: str | None = None


@dataclass
class Session:
    id: str
    username: str
    family_id: str
    created_at: datetime
    revoked: bool = False
    revoke_reason: str | None = None
    revoked_at: datetime | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class WhoamiResponse(BaseModel):
    username: str
    roles: list[str]
    session_id: str
