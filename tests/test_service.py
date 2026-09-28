"""AuthService 层测试：登录、登出、过期、撤销、轮换与复用。"""

from __future__ import annotations

import threading

import pytest

from auth.errors import AuthError, AuthErrorCode


def test_login_success_returns_principal(service):
    _, at, _ = service.login("alice", "alice-pass")
    principal = service.authenticate_access_token(at)
    assert principal.username == "alice"
    assert principal.roles == frozenset({"member"})


@pytest.mark.parametrize(
    "username,password",
    [
        ("alice", "wrong"),
        ("nobody", "alice-pass"),
        ("alice", ""),
    ],
)
def test_login_rejects_bad_credentials_with_same_code(service, username, password):
    with pytest.raises(AuthError) as exc:
        service.login(username, password)
    # 用户不存在/密码错误同码，避免账号枚举
    assert exc.value.code == AuthErrorCode.INVALID_CREDENTIALS


def test_anonymous_is_distinguishable(service):
    with pytest.raises(AuthError) as exc:
        service.authenticate_access_token(None)
    assert exc.value.code == AuthErrorCode.NOT_AUTHENTICATED


def test_unknown_token_distinguishable_from_anonymous(service):
    with pytest.raises(AuthError) as exc:
        service.authenticate_access_token("at_forged")
    assert exc.value.code == AuthErrorCode.INVALID_TOKEN


def test_access_token_expiry_is_distinguishable(service, clock):
    _, at, _ = service.login("alice", "alice-pass")
    clock.advance(11)  # 超过 access_token_ttl=10
    with pytest.raises(AuthError) as exc:
        service.authenticate_access_token(at)
    assert exc.value.code == AuthErrorCode.ACCESS_TOKEN_EXPIRED


def test_refresh_token_expiry_is_distinguishable(service, clock):
    _, _, rt = service.login("alice", "alice-pass")
    clock.advance(61)  # 超过 refresh_token_ttl=60
    with pytest.raises(AuthError) as exc:
        service.rotate_refresh_token(rt)
    assert exc.value.code == AuthErrorCode.REFRESH_TOKEN_EXPIRED


# --------------------------------------------------------------- 轮换与复用
def test_rotation_invalidates_old_refresh_and_old_access(service):
    _, at1, rt1 = service.login("alice", "alice-pass")
    _, at2, rt2 = service.rotate_refresh_token(rt1)

    # 旧访问令牌立即失效（会话只保留最新一枚）
    with pytest.raises(AuthError) as exc:
        service.authenticate_access_token(at1)
    assert exc.value.code == AuthErrorCode.INVALID_TOKEN

    # 新凭证可用
    assert service.authenticate_access_token(at2).username == "alice"


def test_concurrent_refresh_within_grace_does_not_logout(service, clock):
    """同一旧刷新令牌在宽限窗口内几乎同时出现：按并发重试处理，不误判复用。

    工程取舍：宽限重放会把当前链头再轮换一次，因此较早响应中的访问令牌
    会被更新的令牌取代（Cookie 同名覆盖，客户端最终持有的是最新令牌）；
    持有旧响应的一方在窗口内可用其刷新令牌沿链自愈。关键保证是：
    绝不判复用、绝不撤销家族、始终能拿到有效凭证。
    """
    _, _, rt1 = service.login("alice", "alice-pass")

    # 第一次正常轮换：rt1 -> rt2
    _, at2, rt2 = service.rotate_refresh_token(rt1)
    # 极短时间内，客户端因超时重试再次提交 rt1
    clock.advance(0.1)
    _, at3, rt3 = service.rotate_refresh_token(rt1)

    # 最新凭证有效，会话存活
    assert service.authenticate_access_token(at3).username == "alice"

    # 持有第一次响应(rt2)的一方在窗口内可沿链自愈到新链头
    clock.advance(0.1)
    _, at4, rt4 = service.rotate_refresh_token(rt2)
    assert service.authenticate_access_token(at4).username == "alice"

    # 被取代的中间访问令牌不再有效，但这不是"复用"判定，会话没有被撤销：
    # 用最新刷新令牌仍能继续轮换
    with pytest.raises(AuthError) as exc:
        service.authenticate_access_token(at2)
    assert exc.value.code == AuthErrorCode.INVALID_TOKEN
    _, at5, _ = service.rotate_refresh_token(rt3)
    assert service.authenticate_access_token(at5).username == "alice"


def test_reuse_outside_grace_revokes_entire_family(service, clock):
    _, at1, rt1 = service.login("alice", "alice-pass")
    _, at2, rt2 = service.rotate_refresh_token(rt1)
    _, at3, rt3 = service.rotate_refresh_token(rt2)

    # 超过宽限窗口后，被盗的旧令牌重现
    clock.advance(3)
    with pytest.raises(AuthError) as exc:
        service.rotate_refresh_token(rt1)
    assert exc.value.code == AuthErrorCode.TOKEN_REUSE_DETECTED

    # 家族内所有刷新令牌全部失效（包括最新链头）
    for rt in (rt2, rt3):
        with pytest.raises(AuthError) as exc2:
            service.rotate_refresh_token(rt)
        assert exc2.value.code == AuthErrorCode.SESSION_REVOKED

    # 最新访问令牌同样立即失效，且原因可区分
    with pytest.raises(AuthError) as exc3:
        service.authenticate_access_token(at3)
    assert exc3.value.code == AuthErrorCode.SESSION_REVOKED


def test_concurrent_refresh_threads_all_succeed(service):
    """多线程同时用同一旧刷新令牌刷新：全部成功，无一人被踢下线。"""
    _, _, rt1 = service.login("alice", "alice-pass")

    results: list[Exception] = []
    lock = threading.Lock()

    def worker() -> None:
        try:
            service.rotate_refresh_token(rt1)
        except Exception as exc:  # noqa: BLE001 - 测试需要收集一切失败
            with lock:
                results.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results == [], f"并发刷新出现误判: {results!r}"


# ----------------------------------------------------------------- 登出
def test_logout_revokes_all_credentials(service):
    _, at, rt = service.login("alice", "alice-pass")
    service.logout(rt)
    with pytest.raises(AuthError) as exc:
        service.authenticate_access_token(at)
    assert exc.value.code == AuthErrorCode.SESSION_REVOKED
    with pytest.raises(AuthError) as exc2:
        service.rotate_refresh_token(rt)
    assert exc2.value.code == AuthErrorCode.SESSION_REVOKED


def test_logout_is_idempotent(service):
    _, _, rt = service.login("alice", "alice-pass")
    service.logout(rt)
    service.logout(rt)  # 重复登出不报错
    service.logout(rt)
    service.logout(None)  # 无令牌也幂等
    service.logout("rt_unknown_garbage")  # 无法识别也幂等


def test_logout_does_not_touch_other_sessions(service):
    _, at_a, rt_a = service.login("alice", "alice-pass")
    _, at_b, rt_b = service.login("admin", "admin-pass")

    service.logout(rt_a)

    with pytest.raises(AuthError) as exc:
        service.authenticate_access_token(at_a)
    assert exc.value.code == AuthErrorCode.SESSION_REVOKED

    # 另一个会话完全不受影响
    assert service.authenticate_access_token(at_b).username == "admin"
    _, at_b2, _ = service.rotate_refresh_token(rt_b)
    assert service.authenticate_access_token(at_b2).username == "admin"


# -------------------------------------------------------------- 风险撤销
def test_risk_revocation_invalidates_session_immediately(service):
    session, at, rt = service.login("alice", "alice-pass")
    service.revoke_session(session.id, reason="risk")

    with pytest.raises(AuthError) as exc:
        service.authenticate_access_token(at)
    assert exc.value.code == AuthErrorCode.SESSION_REVOKED
    with pytest.raises(AuthError) as exc2:
        service.rotate_refresh_token(rt)
    assert exc2.value.code == AuthErrorCode.SESSION_REVOKED


def test_revoke_is_idempotent(service):
    session, _, _ = service.login("alice", "alice-pass")
    service.revoke_session(session.id)
    service.revoke_session(session.id)  # 不应抛异常
