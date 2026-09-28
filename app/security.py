"""无状态密码学原语：令牌生成、哈希、时间源。

令牌本身只在服务端生成一次并通过 Set-Cookie 下发；存储与日志中只保留
SHA-256 哈希，任何错误响应都不会回带令牌内容。
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timezone


def generate_token(num_bytes: int = 32) -> str:
    """生成 URL 安全的高熵不透明令牌（默认 256 bit 熵）。"""
    return secrets.token_urlsafe(num_bytes)


def hash_token(token: str) -> str:
    """对令牌做 SHA-256，返回十六进制摘要，用于服务端索引与比对。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def utcnow() -> datetime:
    """返回时区感知的 UTC 当前时间。"""
    return datetime.now(tz=timezone.utc)


def constant_time_equals(a: str, b: str) -> bool:
    """常量时间字符串比较，避免密码/令牌比对的计时侧信道。"""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
