"""内存存储：用户表、会话表、刷新令牌表。线程安全。

所有跨实体的复合操作由 AuthService 在 self._lock 内完成；
此处的单次读写方法各自加锁即可。
"""

from __future__ import annotations

import threading

from auth.models import RefreshTokenRecord, Session, User


class AuthStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._users: dict[str, User] = {}
        self._users_by_username: dict[str, str] = {}
        self._sessions: dict[str, Session] = {}
        self._refresh: dict[str, RefreshTokenRecord] = {}
        self._refresh_by_hash: dict[str, str] = {}

    def lock(self) -> threading.RLock:
        """供 Service 把多个操作组合成一个原子临界区。"""
        return self._lock

    # ---- 用户 ----
    def upsert_user(self, user: User) -> None:
        with self._lock:
            self._users[user.id] = user
            self._users_by_username[user.username] = user.id

    def find_user_by_username(self, username: str) -> User | None:
        with self._lock:
            user_id = self._users_by_username.get(username)
            return self._users.get(user_id) if user_id else None

    def get_user(self, user_id: str) -> User | None:
        with self._lock:
            return self._users.get(user_id)

    # ---- 会话 ----
    def save_session(self, session: Session) -> None:
        with self._lock:
            self._sessions[session.id] = session

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def all_sessions(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())

    # ---- 刷新令牌 ----
    def save_refresh(self, record: RefreshTokenRecord) -> None:
        with self._lock:
            self._refresh[record.jti] = record
            self._refresh_by_hash[record.token_hash] = record.jti

    def get_refresh_by_hash(self, token_hash: str) -> str | None:
        with self._lock:
            return self._refresh_by_hash.get(token_hash)

    def get_refresh(self, jti: str) -> RefreshTokenRecord | None:
        with self._lock:
            return self._refresh.get(jti)
