"""鉴权领域服务：登录/登出/刷新/校验/撤销的判定逻辑。

并发刷新与复用检测的工程取舍：
- 每个会话一把互斥锁，把“读刷新令牌 -> 判定 -> 作废旧令牌 -> 签发新令牌”
  串行化；同一张刷新令牌第一次成功使用后被标记为 used 并记录 rotated_at。
- 在 refresh_grace_window_seconds 宽限窗口内再次出现这张 used 令牌时，
  认为是网络重试/客户端几乎同时发起的并发刷新，不撤销任何凭证，而是把
  第一次轮换已经签发的同一对令牌原样返回（窗口内缓存）。
- 超过宽限窗口仍出现 used 令牌，则按凭证泄露处理：撤销整条会话与刷新族，
  所有剩余凭证立即失效，并返回可区分的 refresh_token_reused。
选择“宽限窗口 + 返回同一份新凭证”而不是直接拒绝并发请求，是为了在去重
重试/多标签页并发这种常见正常场景下不误伤合法用户；窗口之外严格处置，
保证泄露检测不被绕过。
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.config import Settings
from app.errors import AuthError, ErrorCode
from app.models import AccessRecord, RefreshRecord, Session, UserRecord
from app.security import constant_time_equals, generate_token, hash_token, utcnow
from app.store import TokenStore

logger = logging.getLogger("app.auth")


def _fingerprint(token: str | None) -> str:
    """只记录令牌哈希的短指纹用于日志关联，绝不记录令牌原文。"""
    if not token:
        return "-"
    return hash_token(token)[:12]


class Clock:
    """可替换/可快进的时间源，测试中可以让令牌立即过期。"""

    def __init__(self) -> None:
        self._offset = timedelta(seconds=0)

    def now(self) -> datetime:
        return utcnow() + self._offset

    def advance(self, seconds: float) -> None:
        self._offset += timedelta(seconds=seconds)


@dataclass
class IssuedTokens:
    access_token: str
    refresh_token: str
    access: AccessRecord
    refresh: RefreshRecord
    session: Session


class AuthService:
    def __init__(self, store: TokenStore, settings: Settings, clock: Clock | None = None):
        self.store = store
        self.settings = settings
        self.clock = clock or Clock()
        # 旧刷新令牌哈希 -> (新访问令牌, 新刷新令牌, 缓存失效时间)
        self._rotation_cache: dict[str, tuple[str, str, datetime]] = {}

    # ---------------- 登录 ----------------
    def login(self, username: str, password: str) -> IssuedTokens:
        user = self.store.find_user(username)
        if user is None:
            # 与“密码错误”走同样路径，避免用户名枚举
            constant_time_equals(password, "not-a-real-password")
            logger.info("auth_decision event=login result=deny reason=invalid_credentials user=%s", username)
            raise AuthError(ErrorCode.INVALID_CREDENTIALS, "用户名或密码错误", 401)
        if not constant_time_equals(password, user.password):
            logger.info("auth_decision event=login result=deny reason=invalid_credentials user=%s", username)
            raise AuthError(ErrorCode.INVALID_CREDENTIALS, "用户名或密码错误", 401)

        now = self.clock.now()
        session = self.store.create_session(username, now)
        tokens = self._issue_tokens(session, now)
        logger.info(
            "auth_decision event=login result=allow user=%s session=%s family=%s",
            username, session.id, session.family_id,
        )
        return tokens

    # ---------------- 登出 ----------------
    def logout(self, refresh_token: str | None) -> None:
        """撤销该刷新令牌所属会话的全部凭证。

        幂等：无令牌、令牌无法识别、会话已撤销，都返回成功且不影响其他会话。
        """
        if not refresh_token:
            logger.info("auth_decision event=logout result=noop reason=no_token")
            return
        record = self.store.get_refresh(hash_token(refresh_token))
        if record is None:
            logger.info("auth_decision event=logout result=noop reason=unknown_token fp=%s",
                        _fingerprint(refresh_token))
            return
        session = self.store.get_session(record.session_id)
        already = session is not None and session.revoked
        self.store.revoke_session(record.session_id, "logout", self.clock.now())
        logger.info(
            "auth_decision event=logout result=ok session=%s family=%s already_revoked=%s",
            record.session_id, record.family_id, already,
        )

    # ---------------- 刷新（轮换 + 复用检测） ----------------
    def refresh(self, refresh_token: str) -> IssuedTokens:
        token_hash = hash_token(refresh_token)
        record = self.store.get_refresh(token_hash)
        now = self.clock.now()

        if record is None:
            logger.info("auth_decision event=refresh result=deny reason=refresh_token_invalid fp=%s",
                        _fingerprint(refresh_token))
            raise AuthError(ErrorCode.REFRESH_TOKEN_INVALID, "刷新令牌无效", 401)

        with self.store.session_lock(record.session_id):
            # 锁内重新读取，保证判定基于最新状态
            record = self.store.get_refresh(token_hash)
            assert record is not None
            session = self.store.get_session(record.session_id)
            now = self.clock.now()

            if session is not None and session.revoked:
                logger.info(
                    "auth_decision event=refresh result=deny reason=session_revoked session=%s fp=%s",
                    session.id, _fingerprint(refresh_token),
                )
                raise AuthError(ErrorCode.SESSION_REVOKED, "会话已结束，请重新登录", 401)

            if record.state == "revoked":
                logger.info(
                    "auth_decision event=refresh result=deny reason=refresh_token_revoked session=%s fp=%s",
                    record.session_id, _fingerprint(refresh_token),
                )
                raise AuthError(ErrorCode.REFRESH_TOKEN_REVOKED, "刷新令牌已作废，请重新登录", 401)

            if now >= record.expires_at:
                logger.info(
                    "auth_decision event=refresh result=deny reason=refresh_token_expired session=%s fp=%s",
                    record.session_id, _fingerprint(refresh_token),
                )
                raise AuthError(ErrorCode.REFRESH_TOKEN_EXPIRED, "刷新令牌已过期，请重新登录", 401)

            if record.state == "used":
                return self._handle_used_refresh(record, refresh_token, now)

            # state == active：执行轮换
            return self._rotate(record, now)

    def _handle_used_refresh(
        self, record: RefreshRecord, presented_token: str, now: datetime
    ) -> IssuedTokens:
        assert record.rotated_at is not None
        within_grace = now - record.rotated_at <= timedelta(
            seconds=self.settings.refresh_grace_window_seconds
        )
        cached = self._rotation_cache.get(hash_token(presented_token))
        cache_fresh = cached is not None and now < cached[2]

        if within_grace and cache_fresh:
            # 正常并发/重试：返回第一次轮换已签发的同一对令牌，不做撤销
            assert cached is not None
            new_access, new_refresh, _ = cached
            session = self.store.get_session(record.session_id)
            access_rec = self.store.get_access(hash_token(new_access))
            refresh_rec = self.store.get_refresh(hash_token(new_refresh))
            assert session is not None and access_rec is not None and refresh_rec is not None
            logger.info(
                "auth_decision event=refresh result=allow mode=concurrent_replay session=%s fp=%s",
                record.session_id, _fingerprint(presented_token),
            )
            return IssuedTokens(new_access, new_refresh, access_rec, refresh_rec, session)

        # 超出宽限窗口仍使用旧令牌：判定为复用/泄露，撤销整条会话
        record.reuse_seen = True
        self.store.revoke_session(record.session_id, "refresh_token_reuse", now)
        self._rotation_cache.pop(hash_token(presented_token), None)
        logger.warning(
            "auth_decision event=refresh result=deny reason=refresh_token_reused session=%s family=%s fp=%s",
            record.session_id, record.family_id, _fingerprint(presented_token),
        )
        raise AuthError(ErrorCode.REFRESH_TOKEN_REUSED, "检测到异常访问，请重新登录", 401)

    def _rotate(self, old_record: RefreshRecord, now: datetime) -> IssuedTokens:
        session = self.store.get_session(old_record.session_id)
        assert session is not None

        new_access_plain, new_refresh_plain, new_access, new_refresh = self._new_token_records(
            session, now
        )
        # 先写新令牌，再把旧令牌标记为 used，记录轮换时刻用于宽限判定
        self.store.put_access(hash_token(new_access_plain), new_access)
        self.store.put_refresh(hash_token(new_refresh_plain), new_refresh)
        old_record.state = "used"
        old_record.rotated_at = now
        old_record.replaced_by_jti = new_refresh.jti
        self._rotation_cache[hash_token_of(old_record)] = (
            new_access_plain,
            new_refresh_plain,
            now + timedelta(seconds=self.settings.refresh_grace_window_seconds),
        )
        logger.info(
            "auth_decision event=refresh result=allow mode=rotate session=%s family=%s old_fp=%s new_fp=%s",
            session.id, session.family_id, old_record.jti[:12], hash_token(new_refresh_plain)[:12],
        )
        return IssuedTokens(new_access_plain, new_refresh_plain, new_access, new_refresh, session)

    # ---------------- 访问令牌校验 ----------------
    def authenticate_access(self, token: str | None) -> AccessRecord:
        if not token:
            logger.info("auth_decision event=access result=deny reason=access_token_missing")
            raise AuthError(ErrorCode.ACCESS_TOKEN_MISSING, "未提供访问令牌", 401)

        record = self.store.get_access(hash_token(token))
        if record is None:
            logger.info("auth_decision event=access result=deny reason=access_token_invalid fp=%s",
                        _fingerprint(token))
            raise AuthError(ErrorCode.ACCESS_TOKEN_INVALID, "访问令牌无效", 401)

        session = self.store.get_session(record.session_id)
        if session is not None and session.revoked:
            logger.info("auth_decision event=access result=deny reason=session_revoked session=%s",
                        record.session_id)
            raise AuthError(ErrorCode.SESSION_REVOKED, "会话已结束，请重新登录", 401)
        if record.revoked:
            logger.info("auth_decision event=access result=deny reason=access_token_revoked session=%s",
                        record.session_id)
            raise AuthError(ErrorCode.ACCESS_TOKEN_REVOKED, "访问令牌已作废", 401)
        now = self.clock.now()
        if now >= record.expires_at:
            logger.info("auth_decision event=access result=deny reason=access_token_expired session=%s",
                        record.session_id)
            raise AuthError(ErrorCode.ACCESS_TOKEN_EXPIRED, "访问令牌已过期", 401)

        logger.info("auth_decision event=access result=allow session=%s user=%s",
                    record.session_id, record.username)
        return record

    def user_for(self, username: str) -> UserRecord:
        user = self.store.find_user(username)
        if user is None:  # 理论上不会发生：令牌必然属于已存在用户
            raise AuthError(ErrorCode.ACCESS_TOKEN_INVALID, "访问令牌无效", 401)
        return user

    # ---------------- 管理操作 ----------------
    def revoke_session_by_admin(self, session_id: str) -> bool:
        session = self.store.get_session(session_id)
        if session is None:
            return False
        self.store.revoke_session(session_id, "admin_risk_revoke", self.clock.now())
        logger.warning("auth_decision event=admin_revoke result=ok session=%s user=%s",
                       session_id, session.username)
        return True

    def list_sessions(self, username: str) -> list[Session]:
        return self.store.list_user_sessions(username)

    # ---------------- 内部工具 ----------------
    def _issue_tokens(self, session: Session, now: datetime) -> IssuedTokens:
        access_plain, refresh_plain, access_rec, refresh_rec = self._new_token_records(session, now)
        self.store.put_access(hash_token(access_plain), access_rec)
        self.store.put_refresh(hash_token(refresh_plain), refresh_rec)
        return IssuedTokens(access_plain, refresh_plain, access_rec, refresh_rec, session)

    def _new_token_records(
        self, session: Session, now: datetime
    ) -> tuple[str, str, AccessRecord, RefreshRecord]:
        access_plain = generate_token()
        refresh_plain = generate_token()
        access_rec = AccessRecord(
            jti=hash_token(access_plain),
            session_id=session.id,
            username=session.username,
            expires_at=now + timedelta(seconds=self.settings.access_token_ttl_seconds),
        )
        refresh_rec = RefreshRecord(
            jti=hash_token(refresh_plain),
            session_id=session.id,
            family_id=session.family_id,
            expires_at=now + timedelta(seconds=self.settings.refresh_token_ttl_seconds),
        )
        return access_plain, refresh_plain, access_rec, refresh_rec


def hash_token_of(record: RefreshRecord) -> str:
    """刷新记录以其令牌哈希为主键，jti 即该哈希。"""
    return record.jti
