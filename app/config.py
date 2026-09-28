"""配置项：令牌有效期、Cookie、并发刷新宽限窗口、演示用户。

所有时长单位均为秒，可通过环境变量覆盖，便于本地与测试使用不同取值。
"""

import os
from dataclasses import dataclass, field

from app.models import UserRecord


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw is not None and raw.strip() else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def default_users() -> tuple[UserRecord, ...]:
    """内置演示账户：一个管理员 + 两个普通成员。"""
    return (
        UserRecord("admin", "admin123", ("admin", "member")),
        UserRecord("alice", "alice123", ("member",)),
        UserRecord("bob", "bob123", ("member",)),
    )


@dataclass(frozen=True)
class Settings:
    # 访问令牌：短时效，默认 15 分钟
    access_token_ttl_seconds: int = 900
    # 刷新令牌：长时效，默认 14 天
    refresh_token_ttl_seconds: int = 60 * 60 * 24 * 14
    # 并发刷新宽限窗口：同一张刷新令牌在窗口内被并发使用视为同一次轮换，
    # 返回同一份新凭证，避免正常重试/并发被误判成令牌复用。
    refresh_grace_window_seconds: int = 30

    # Cookie 属性
    cookie_secure: bool = False
    cookie_samesite: str = "lax"
    cookie_path: str = "/"

    # 演示用户库
    users: tuple[UserRecord, ...] = field(default_factory=default_users)


def get_settings() -> Settings:
    """从环境变量读取配置（未设置时使用安全默认值）。"""
    return Settings(
        access_token_ttl_seconds=_env_int("ACCESS_TOKEN_TTL_SECONDS", 900),
        refresh_token_ttl_seconds=_env_int("REFRESH_TOKEN_TTL_SECONDS", 60 * 60 * 24 * 14),
        refresh_grace_window_seconds=_env_int("REFRESH_GRACE_WINDOW_SECONDS", 30),
        cookie_secure=_env_bool("COOKIE_SECURE", False),
        cookie_samesite=os.environ.get("COOKIE_SAMESITE", "lax"),
        cookie_path=os.environ.get("COOKIE_PATH", "/"),
    )
