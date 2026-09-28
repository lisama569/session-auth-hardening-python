"""令牌过期、会话撤销、登出生命周期。"""


def test_access_token_expiry_is_distinguishable(env):
    _, access, _ = env.login("alice", "alice123")
    assert env.client.get("/me", headers=env.bearer(access)).status_code == 200

    env.clock.advance(3)  # 超过 access_token_ttl_seconds=2
    r = env.client.get("/me", headers=env.bearer(access))
    env.assert_decision("过期访问令牌", r, 401, "access_token_expired", secret=access)


def test_expired_access_token_can_be_refreshed(env):
    _, access, refresh = env.login("alice", "alice123")
    env.clock.advance(3)
    r = env.client.get("/me", headers=env.bearer(access))
    env.assert_decision("刷新前访问被拒", r, 401, "access_token_expired")

    # 刷新接口使用刷新 Cookie（TestClient 已保存），换取新访问令牌
    r = env.client.post("/auth/refresh")
    assert r.status_code == 200
    new_access = r.cookies.get("access_token")
    assert new_access != access
    me = env.client.get("/me")  # 新 Cookie 自动携带
    assert me.status_code == 200
    assert me.json()["username"] == "alice"


def test_logout_revokes_session_and_is_idempotent(env):
    _, access, refresh = env.login("alice", "alice123")
    first = env.client.post("/auth/logout")
    assert first.status_code == 200
    second = env.client.post("/auth/logout")  # 重复登出不得报错
    assert second.status_code == 200

    r = env.client.get("/me", headers=env.bearer(access))
    env.assert_decision("登出后旧访问令牌立即失效", r, 401, "session_revoked")

    r = env.client.post("/auth/refresh", headers=env.raw_cookie(refresh=refresh))
    env.assert_decision("登出后刷新令牌不可用", r, 401, "session_revoked")


def test_logout_does_not_touch_other_sessions(env):
    _, a_access, a_refresh = env.login("alice", "alice123")
    _, b_access, b_refresh = env.login("bob", "bob123")

    # 用独立客户端登出 alice，避免 Cookie 串扰
    env.client.post("/auth/logout", headers=env.raw_cookie(refresh=a_refresh))
    # bob 的会话仍然有效
    assert env.client.get("/me", headers=env.bearer(b_access)).status_code == 200
    r = env.client.post("/auth/refresh", headers=env.raw_cookie(refresh=b_refresh))
    assert r.status_code == 200

    # alice 已下线
    r = env.client.get("/me", headers=env.bearer(a_access))
    env.assert_decision("仅 alice 被登出", r, 401, "session_revoked")


def test_refresh_without_token_is_missing(env):
    r = env.client.post("/auth/refresh")
    env.assert_decision("无刷新令牌", r, 401, "refresh_token_missing")


def test_unknown_refresh_token_is_invalid(env):
    r = env.client.post("/auth/refresh",
                        headers=env.raw_cookie(refresh="made-up-refresh-token"))
    env.assert_decision("无法识别的刷新令牌", r, 401, "refresh_token_invalid",
                        secret="made-up-refresh-token")


def test_refresh_token_expiry_is_distinguishable(env):
    _, _, refresh = env.login("alice", "alice123")
    env.clock.advance(61)  # 超过 refresh_token_ttl_seconds=60
    r = env.client.post("/auth/refresh", headers=env.raw_cookie(refresh=refresh))
    env.assert_decision("过期刷新令牌", r, 401, "refresh_token_expired", secret=refresh)


def test_admin_risk_revocation_kills_all_credentials(env):
    _, admin_access, _ = env.login("admin", "admin123")
    _, alice_access, alice_refresh = env.login("alice", "alice123")
    session_id = env.client.get("/me", headers=env.bearer(alice_access)).json()["session_id"]

    r = env.client.post(
        f"/admin/sessions/{session_id}/revoke",
        headers=env.bearer(admin_access),
    )
    assert r.status_code == 200 and r.json()["revoked"] is True

    r = env.client.get("/me", headers=env.bearer(alice_access))
    env.assert_decision("风控撤销后访问令牌立即失效", r, 401, "session_revoked")
    r = env.client.post("/auth/refresh", headers=env.raw_cookie(refresh=alice_refresh))
    env.assert_decision("风控撤销后刷新令牌立即失效", r, 401, "session_revoked")


def test_member_cannot_revoke_sessions(env):
    _, member_access, _ = env.login("alice", "alice123")
    r = env.client.post("/admin/sessions/whatever/revoke",
                        headers=env.bearer(member_access))
    env.assert_decision("普通成员调用风控撤销", r, 403, "permission_denied")
