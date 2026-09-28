"""认证核心服务：登录、登出、刷新（轮换 + 复用检测）、访问令牌校验。

并发刷新的工程取舍
------------------
刷新令牌构成一条单链：R1(ACTIVE) -> 轮换后 R1(ROTATED, successor=R2)。
当一张已轮换的旧令牌再次出现时：

* 若距离它被轮换不超过 ``rotation_grace_seconds``（默认 30s），视为客户端
  并发刷新或响应丢失后的重试：沿后继链走到当前 ACTIVE 头部，从头部继续
  正常轮换。合法并发请求都能拿到可用的新令牌，且链始终保持单一头部，
  不会把用户误踢下线。
* 若超过宽限窗口，旧令牌重现即判定为凭证泄露：撤销整条会话家族（访问令牌
  + 所有刷新令牌立即失效），对外返回稳定错误码 token_reuse_detected。

宽限窗口是"可用性/安全"的显式折中：窗口内被盗的旧令牌同样会被接受，
因此窗口应只略大于客户端合理的请求/重试耗时（默认 30s）；窗口外的复用
一定会被发现并完成家族撤销。

日志只打印输入（用户名）与判定依据（jti 短码、哈希指纹前缀、状态、时效），
绝不打印令牌明文。
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

from auth.config import AuthConfig
from auth.errors import AuthError, AuthErrorCode
from auth.models import Principal, RefreshTokenRecord, Session
from auth.security import (
    check_password,
    constant_time_equals,
    generate_token,
    hash_token,
)
from auth.store import AuthStore

log = logging.getLogger("auth.service")

_STATUS_ACTIVE = "ACTIVE"
_STATUS_ROTATED = "ROTATED"
_STATUS_REVOKED = "REVOKED"


def _fp(token_hash: str) -> str:
    """哈希指纹前缀：可用于日志关联，但无法还原令牌。"""
    return token_hash[:8]


class AuthService:
    def __init__(
        self,
        store: AuthStore,
        config: AuthConfig | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.store = store
        self.config: AuthConfig = config or AuthConfig()
        # 可注入时钟，便于测试中快进而不必真实等待
        self._clock: Callable[[], float] = clock or time.time

    def _now(self) -> float:
        return self._clock()

    # ---------------------------------------------------------------- 登录
    def login(self, username: str, password: str) -> tuple[Session, str, str]:
        """成功返回 (session, 明文访问令牌, 明文刷新令牌)。"""
        now = self._now()
        user = self.store.find_user_by_username(username)
        # 用户不存在与口令错误返回同一错误，避免账号枚举
        if user is None or not check_password(password, user.password_sha256):
            log.info(
                "login rejected input_user=%s basis=user_not_found_or_bad_password",
                username,
            )
            raise AuthError(AuthErrorCode.INVALID_CREDENTIALS)

        with self.store.lock():
            session = Session(
                id=generate_token()[0],
                user_id=user.id,
                created_at=now,
                last_seen_at=now,
            )
            self.store.save_session(session)
            raw_access, raw_refresh = self._issue_tokens(session, now)
            log.info(
                "login accepted input_user=%s session=%s basis=password_verified",
                username,
                session.id[:8],
            )
            return session, raw_access, raw_refresh

    # ------------------------------------------------------------ 幂等登出
    def logout(self, refresh_token: str | None) -> None:
        """按刷新令牌撤销整条会话。

        无令牌 / 令牌无法识别 / 会话已撤销：全部幂等返回 200，不报错；
        只撤销该令牌所属会话，绝不影响其他会话。
        """
        if not refresh_token:
            log.info("logout idempotent basis=no_refresh_token_presented")
            return

        token_hash = hash_token(refresh_token)
        with self.store.lock():
            jti = self.store.get_refresh_by_hash(token_hash)
            if jti is None:
                # 无法识别的令牌：可能已过期清理或为伪造，重复登出同样走到这里
                log.info(
                    "logout idempotent token_fp=%s basis=refresh_token_unknown",
                    _fp(token_hash),
                )
                return
            record = self.store.get_refresh(jti)
            session = self.store.get_session(record.session_id)
            if session is None or session.revoked:
                log.info(
                    "logout idempotent session=%s basis=session_already_revoked_or_missing",
                    record.session_id[:8],
                )
                return
            self._revoke_session_locked(session, reason="logout")
            log.info(
                "logout accepted session=%s basis=user_initiated family_revoked",
                session.id[:8],
            )

    # ------------------------------------------------- 刷新：轮换 + 复用检测
    def rotate_refresh_token(
        self, presented_refresh_token: str | None
    ) -> tuple[Session, str, str]:
        if not presented_refresh_token:
            raise AuthError(AuthErrorCode.NOT_AUTHENTICATED)

        token_hash = hash_token(presented_refresh_token)
        with self.store.lock():
            now = self._now()
            jti = self.store.get_refresh_by_hash(token_hash)
            if jti is None:
                log.info(
                    "refresh rejected token_fp=%s basis=refresh_token_unknown",
                    _fp(token_hash),
                )
                raise AuthError(AuthErrorCode.INVALID_TOKEN)

            record = self.store.get_refresh(jti)
            session = self.store.get_session(record.session_id)
            if session is None:
                log.info(
                    "refresh rejected token_fp=%s basis=session_missing",
                    _fp(token_hash),
                )
                raise AuthError(AuthErrorCode.INVALID_TOKEN)
            if session.revoked:
                log.info(
                    "refresh rejected session=%s token_jti=%s basis=session_revoked",
                    session.id[:8],
                    record.jti[:8],
                )
                raise AuthError(AuthErrorCode.SESSION_REVOKED)
            if self._idle_expired_locked(session, now):
                self._revoke_session_locked(session, reason="idle_timeout")
                log.info(
                    "refresh rejected session=%s basis=idle_timeout_exceeded family_revoked",
                    session.id[:8],
                )
                raise AuthError(AuthErrorCode.SESSION_REVOKED)

            if record.status == _STATUS_ROTATED:
                head = self._resolve_concurrent_replay_locked(record, now, session)
                # head 为应从其继续轮换的当前有效令牌
                return self._do_rotation_locked(head, session, now, replay=True)

            if record.status == _STATUS_REVOKED:
                log.info(
                    "refresh rejected session=%s token_jti=%s basis=token_revoked",
                    session.id[:8],
                    record.jti[:8],
                )
                raise AuthError(AuthErrorCode.SESSION_REVOKED)

            # ACTIVE
            if record.is_expired(now):
                log.info(
                    "refresh rejected session=%s token_jti=%s "
                    "basis=refresh_token_expired age=%.1f",
                    session.id[:8],
                    record.jti[:8],
                    now - record.expires_at,
                )
                raise AuthError(AuthErrorCode.REFRESH_TOKEN_EXPIRED)

            return self._do_rotation_locked(record, session, now, replay=False)

    def _resolve_concurrent_replay_locked(
        self, record: RefreshTokenRecord, now: float, session: Session
    ) -> RefreshTokenRecord:
        """处理一张已轮换令牌的重现，返回当前可轮换的 ACTIVE 头部。

        超出宽限窗口 => 复用攻击，撤销家族并抛错；
        窗口内 => 沿后继链走到头部（并发/重试场景）。
        """
        grace = self.config.rotation_grace_seconds
        age = now - (record.rotated_at or record.issued_at)
        if age > grace:
            self._revoke_session_locked(session, reason="refresh_token_reuse")
            log.warning(
                "refresh REUSE DETECTED session=%s old_jti=%s age=%.1fs "
                "basis=rotated_token_outside_grace family_revoked",
                session.id[:8],
                record.jti[:8],
                age,
            )
            raise AuthError(AuthErrorCode.TOKEN_REUSE_DETECTED)

        # 宽限窗口内：沿单链找到当前 ACTIVE 头部
        head = record
        seen: set[str] = set()
        while head.successor_jti and head.successor_jti not in seen:
            seen.add(head.jti)
            nxt = self.store.get_refresh(head.successor_jti)
            if nxt is None:
                break
            if nxt.status == _STATUS_REVOKED:
                log.info(
                    "refresh rejected session=%s basis=successor_revoked",
                    session.id[:8],
                )
                raise AuthError(AuthErrorCode.SESSION_REVOKED)
            head = nxt
            if head.status == _STATUS_ACTIVE:
                break

        if head.status != _STATUS_ACTIVE:
            # 理论不可达：未撤销的链末端必为 ACTIVE
            log.warning(
                "refresh rejected session=%s basis=no_active_head_in_chain",
                session.id[:8],
            )
            raise AuthError(AuthErrorCode.INVALID_TOKEN)
        if head.is_expired(now):
            log.info(
                "refresh rejected session=%s head_jti=%s basis=head_expired",
                session.id[:8],
                head.jti[:8],
            )
            raise AuthError(AuthErrorCode.REFRESH_TOKEN_EXPIRED)

        log.info(
            "refresh concurrent-replay accepted session=%s old_jti=%s head_jti=%s "
            "age=%.3fs basis=rotated_token_within_grace",
            session.id[:8],
            record.jti[:8],
            head.jti[:8],
            age,
        )
        return head

    def _do_rotation_locked(
        self,
        head: RefreshTokenRecord,
        session: Session,
        now: float,
        *,
        replay: bool,
    ) -> tuple[Session, str, str]:
        # 发放一对新令牌
        raw_access, raw_refresh = self._issue_tokens(session, now)
        new_jti = session.refresh_jtis[-1]
        # 旧头部标记为已轮换，指向后继
        head.status = _STATUS_ROTATED
        head.rotated_at = now
        head.successor_jti = new_jti
        self.store.save_refresh(head)
        session.last_seen_at = now
        self.store.save_session(session)
        log.info(
            "rotation ok session=%s old_jti=%s new_jti=%s basis=%s",
            session.id[:8],
            head.jti[:8],
            new_jti[:8],
            "concurrent_replay_within_grace" if replay else "normal_rotation",
        )
        return session, raw_access, raw_refresh

    # -------------------------------------------------------- 访问令牌校验
    def authenticate_access_token(self, raw: str | None) -> Principal:
        if not raw:
            log.info("access denied basis=no_access_token state=anonymous")
            raise AuthError(AuthErrorCode.NOT_AUTHENTICATED)

        token_hash = hash_token(raw)
        with self.store.lock():
            now = self._now()
            session = self._find_session_by_access_hash_locked(token_hash)
            if session is None:
                log.info(
                    "access denied token_fp=%s basis=access_token_unknown",
                    _fp(token_hash),
                )
                raise AuthError(AuthErrorCode.INVALID_TOKEN)
            if session.revoked:
                log.info(
                    "access denied session=%s basis=session_revoked reason=%s",
                    session.id[:8],
                    session.revoke_reason,
                )
                raise AuthError(AuthErrorCode.SESSION_REVOKED)
            if now >= session.access_token_expires_at:
                log.info(
                    "access denied session=%s basis=access_token_expired",
                    session.id[:8],
                )
                raise AuthError(AuthErrorCode.ACCESS_TOKEN_EXPIRED)
            if self._idle_expired_locked(session, now):
                self._revoke_session_locked(session, reason="idle_timeout")
                log.info(
                    "access denied session=%s basis=idle_timeout_exceeded family_revoked",
                    session.id[:8],
                )
                raise AuthError(AuthErrorCode.SESSION_REVOKED)

            user = self.store.get_user(session.user_id)
            if user is None:
                log.info(
                    "access denied session=%s basis=user_missing",
                    session.id[:8],
                )
                raise AuthError(AuthErrorCode.INVALID_TOKEN)

            session.last_seen_at = now
            self.store.save_session(session)
            return Principal(
                user_id=user.id,
                username=user.username,
                roles=user.roles,
                session_id=session.id,
            )

    def _find_session_by_access_hash_locked(self, token_hash: str) -> Session | None:
        for session in self.store.all_sessions():
            stored = session.access_token_hash
            if stored is not None and constant_time_equals(stored, token_hash):
                return session
        return None

    # -------------------------------------------------------------- 风险撤销
    def revoke_session(self, session_id: str, reason: str = "risk") -> None:
        """管理员/风控调用：撤销整条会话，剩余凭证立即失效。"""
        with self.store.lock():
            session = self.store.get_session(session_id)
            if session is None or session.revoked:
                log.info(
                    "revoke idempotent session=%s basis=missing_or_already_revoked",
                    session_id[:8],
                )
                return
            self._revoke_session_locked(session, reason=reason)
            log.warning(
                "session revoked session=%s reason=%s basis=administrative_or_risk",
                session_id[:8],
                reason,
            )

    # ---------------------------------------------------------------- 内部
    def _issue_tokens(self, session: Session, now: float) -> tuple[str, str]:
        """在调用方持锁的前提下，为会话签发一对新令牌并落库。"""
        at_jti, raw_access, at_hash = generate_token("at_")
        rt_jti, raw_refresh, rt_hash = generate_token("rt_")

        session.access_token_hash = at_hash
        session.access_token_expires_at = now + self.config.access_token_ttl

        record = RefreshTokenRecord(
            jti=rt_jti,
            token_hash=rt_hash,
            session_id=session.id,
            issued_at=now,
            expires_at=now + self.config.refresh_token_ttl,
            status=_STATUS_ACTIVE,
        )
        self.store.save_refresh(record)
        session.refresh_jtis.append(rt_jti)
        self.store.save_session(session)
        return raw_access, raw_refresh

    def _revoke_session_locked(self, session: Session, *, reason: str) -> None:
        """调用方持锁。访问令牌与家族内全部刷新令牌立即失效。

        访问令牌哈希刻意保留：这样旧令牌重现时仍能定位到会话并给出可区分的
        session_revoked，而不是与伪造令牌混淆成 invalid_token。revoked 标志
        在所有校验中最先判定，保留哈希本身不会带来任何可用性。
        """
        session.revoked = True
        session.revoke_reason = reason
        session.access_token_expires_at = 0.0
        for jti in session.refresh_jtis:
            record = self.store.get_refresh(jti)
            if record is not None and record.status != _STATUS_REVOKED:
                record.status = _STATUS_REVOKED
                self.store.save_refresh(record)
        self.store.save_session(session)

    def _idle_expired_locked(self, session: Session, now: float) -> bool:
        if not session.last_seen_at:
            return False
        return now - session.last_seen_at > self.config.idle_timeout_seconds
