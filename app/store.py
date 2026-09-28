"""内存会话/令牌存储：所有判定依据集中在这里，便于加锁与审计。

索引设计：
- sessions：session_id -> Session；user_sessions：username -> [session_id]
- accesses：令牌哈希 -> AccessRecord；access_by_session：会话 -> 哈希集合
- refreshes：令牌哈希 -> RefreshRecord；refresh_by_family：族 -> 哈希集合

撤销会话 = 原子地把会话标记撤销，并作废该会话/刷新族下的全部凭证，
保证“登出/风险判定后剩余凭证立即失效”。
"""

import threading
from datetime import datetime

from app.models import AccessRecord, RefreshRecord, Session, UserRecord


class TokenStore:
    def __init__(self, users: list[UserRecord]):
        self._users: dict[str, UserRecord] = {u.username: u for u in users}
        self._sessions: dict[str, Session] = {}
        self._user_sessions: dict[str, list[str]] = {}
        self._accesses: dict[str, AccessRecord] = {}
        self._access_by_session: dict[str, set[str]] = {}
        self._refreshes: dict[str, RefreshRecord] = {}
        self._refresh_by_family: dict[str, set[str]] = {}
        self._lock = threading.RLock()
        self._session_locks: dict[str, threading.Lock] = {}

    # ---------- 用户 ----------
    def find_user(self, username: str) -> UserRecord | None:
        with self._lock:
            return self._users.get(username)

    # ---------- 会话 ----------
    def create_session(self, username: str, now: datetime) -> Session:
        import secrets

        session = Session(
            id=secrets.token_hex(16),
            username=username,
            family_id=secrets.token_hex(16),
            created_at=now,
        )
        with self._lock:
            self._sessions[session.id] = session
            self._user_sessions.setdefault(username, []).append(session.id)
            self._access_by_session[session.id] = set()
            self._refresh_by_family[session.family_id] = set()
        return session

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def list_user_sessions(self, username: str) -> list[Session]:
        with self._lock:
            return [
                self._sessions[sid]
                for sid in self._user_sessions.get(username, [])
                if sid in self._sessions
            ]

    def revoke_session(self, session_id: str, reason: str, now: datetime) -> None:
        """撤销整条会话：会话本身 + 其全部访问令牌 + 刷新族全部令牌。幂等。"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.revoked:
                return
            session.revoked = True
            session.revoke_reason = reason
            session.revoked_at = now
            for jti in self._access_by_session.get(session_id, set()):
                record = self._accesses.get(jti)
                if record is not None:
                    record.revoked = True
            family = self._refresh_by_family.get(session.family_id, set())
            for token_hash in family:
                record = self._refreshes.get(token_hash)
                if record is not None and record.state != "revoked":
                    record.state = "revoked"

    # ---------- 访问令牌 ----------
    def put_access(self, token_hash: str, record: AccessRecord) -> None:
        with self._lock:
            self._accesses[token_hash] = record
            self._access_by_session.setdefault(record.session_id, set()).add(token_hash)

    def get_access(self, token_hash: str) -> AccessRecord | None:
        with self._lock:
            return self._accesses.get(token_hash)

    # ---------- 刷新令牌 ----------
    def put_refresh(self, token_hash: str, record: RefreshRecord) -> None:
        with self._lock:
            self._refreshes[token_hash] = record
            self._refresh_by_family.setdefault(record.family_id, set()).add(token_hash)

    def get_refresh(self, token_hash: str) -> RefreshRecord | None:
        with self._lock:
            return self._refreshes.get(token_hash)

    # 兼容服务层早期命名
    def get_refresh_by_hash(self, token_hash: str) -> RefreshRecord | None:
        return self.get_refresh(token_hash)

    # ---------- 锁 ----------
    def session_lock(self, session_id: str) -> threading.Lock:
        """返回会话级互斥锁，把“读令牌-判定-轮换-写回”串行化。"""
        with self._lock:
            lock = self._session_locks.get(session_id)
            if lock is None:
                lock = threading.Lock()
                self._session_locks[session_id] = lock
            return lock
