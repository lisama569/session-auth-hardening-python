"""领域模型：用户、会话、刷新令牌记录、认证主体。"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class User:
    id: str
    username: str
    password_sha256: str
    roles: frozenset[str]


@dataclass
class RefreshTokenRecord:
    """一条刷新令牌的服务端记录。只存哈希，永不存明文。"""

    jti: str
    token_hash: str
    session_id: str
    issued_at: float
    expires_at: float
    # ACTIVE: 当前有效；ROTATED: 已被轮换（宽限期内可能服务并发刷新）；
    # REVOKED: 已作废
    status: str = "ACTIVE"
    rotated_at: float | None = None
    # 轮换后继令牌：宽限期内并发刷新时用来发放同一对后继凭证
    successor_jti: str | None = None

    def is_expired(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return now >= self.expires_at


@dataclass
class Session:
    id: str
    user_id: str
    created_at: float
    revoked: bool = False
    revoke_reason: str | None = None
    last_seen_at: float = 0.0
    # 当前访问令牌哈希；登出/风险撤销时清空以立即失效
    access_token_hash: str | None = None
    access_token_expires_at: float = 0.0
    # 会话下所有刷新令牌 jti
    refresh_jtis: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Principal:
    """通过认证后交给入口层的身份主体。"""

    user_id: str
    username: str
    roles: frozenset[str]
    session_id: str
