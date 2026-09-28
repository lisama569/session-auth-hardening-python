"""认证相关配置。"""

from dataclasses import dataclass

# Cookie 名称常量（避免 deps/routes 循环导入）
ACCESS_COOKIE = "sid_at"
REFRESH_COOKIE = "sid_rt"


@dataclass(frozen=True)
class AuthConfig:
    """认证参数。所有时长单位为秒。"""

    access_token_ttl: int = 15 * 60
    refresh_token_ttl: int = 14 * 24 * 60 * 60
    # 并发刷新宽限窗口：旧刷新令牌轮换后，在此窗口内再次提交
    # 视为客户端并发重试，而非令牌复用攻击。
    rotation_grace_seconds: int = 30
    # 会话在无活动多久后整体失效
    idle_timeout_seconds: int = 7 * 24 * 60 * 60
    cookie_secure: bool = False
    cookie_samesite: str = "lax"
    cookie_path: str = "/"


config = AuthConfig()
