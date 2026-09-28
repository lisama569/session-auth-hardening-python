"""令牌生成与哈希原语。"""

from __future__ import annotations

import hashlib
import hmac
import secrets


def generate_token(prefix: str = "") -> tuple[str, str, str]:
    """生成一个不透明随机令牌。

    返回 (jti, 明文令牌, 令牌哈希)。明文只出现一次，用于写入 Cookie；
    服务端只持久化哈希，数据库泄露也无法直接冒用。
    """
    jti = uuid4_hex()
    raw = f"{prefix}{secrets.token_urlsafe(32)}" if prefix else secrets.token_urlsafe(32)
    return jti, raw, hash_token(raw)


def uuid4_hex() -> str:
    import uuid

    return uuid.uuid4().hex


def hash_token(token: str) -> str:
    # SHA-256 足够：输入为 256 位 CSPRNG 随机量，不存在离线爆破面
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def hash_password(password: str) -> str:
    # 演示用途的口令存储。生产应使用 bcrypt/argon2 加盐慢哈希。
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def check_password(password: str, password_sha256: str) -> bool:
    candidate = hash_password(password)
    return hmac.compare_digest(candidate, password_sha256)
