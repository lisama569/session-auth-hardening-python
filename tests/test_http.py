"""HTTP 端到端测试：Cookie 会话、各入口拒绝原因一致性、RBAC。"""

from __future__ import annotations

from fastapi.testclient import TestClient


def _login(client: TestClient, username: str, password: str):
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    assert "sid_at" in client.cookies and "sid_rt" in client.cookies
    return resp


# ------------------------------------------------------------------ 匿名
def test_anonymous_access_is_401_with_distinguishable_code(client):
    client.cookies.clear()
    for path in ("/auth/me", "/member/area", "/admin/users"):
        resp = client.get(path)
        assert resp.status_code == 401, path
        assert resp.json() == {"error": "not_authenticated"}, path


def test_forged_cookie_is_invalid_token_not_anonymous(client):
    client.cookies.clear()
    client.cookies.set("sid_at", "at_forged")
    resp = client.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid_token"}


# ------------------------------------------------------------------ 登录
def test_login_bad_credentials(client):
    resp = client.post("/auth/login", json={"username": "alice", "password": "nope"})
    assert resp.status_code == 401
    body = resp.json()
    assert body == {"error": "invalid_credentials"}
    # 错误响应不得携带任何令牌内容
    assert "sid_" not in resp.text


def test_login_sets_httponly_cookies(client):
    resp = _login(client, "alice", "alice-pass")
    set_cookie = [
        v for k, v in resp.headers.items() if k.lower() == "set-cookie"
    ]
    assert any("sid_at=" in c and "HttpOnly" in c for c in set_cookie)
    assert any("sid_rt=" in c and "HttpOnly" in c for c in set_cookie)


def test_me_after_login(client):
    _login(client, "alice", "alice-pass")
    resp = client.get("/auth/me")
    assert resp.status_code == 200
    assert resp.json()["username"] == "alice"
    assert resp.json()["roles"] == ["member"]


# ------------------------------------------------------------------ RBAC
def test_rbac_member_allowed_member_area_denied_admin(client):
    _login(client, "alice", "alice-pass")
    ok = client.get("/member/area")
    assert ok.status_code == 200

    denied = client.get("/admin/users")
    assert denied.status_code == 403
    assert denied.json() == {"error": "forbidden"}
    # 无权限错误不得泄露内部细节或令牌
    assert "sid_" not in denied.text


def test_rbac_admin_can_access_admin(client):
    _login(client, "admin", "admin-pass")
    assert client.get("/admin/users").status_code == 200
    assert client.get("/member/area").status_code == 200


# ------------------------------------------------------------ 访问令牌过期
def test_expired_access_token_code_and_refresh_recovery(client, clock):
    _login(client, "alice", "alice-pass")
    clock.advance(11)  # 访问令牌过期，刷新令牌仍有效

    resp = client.get("/auth/me")
    assert resp.status_code == 401
    assert resp.json() == {"error": "access_token_expired"}

    # 用刷新令牌续期后恢复
    refreshed = client.post("/auth/refresh")
    assert refreshed.status_code == 200
    assert client.get("/auth/me").status_code == 200


def test_expired_refresh_token_blocks_refresh(client, clock):
    _login(client, "alice", "alice-pass")
    clock.advance(61)
    resp = client.post("/auth/refresh")
    assert resp.status_code == 401
    assert resp.json() == {"error": "refresh_token_expired"}


# ------------------------------------------------------------ 轮换与复用
def test_http_refresh_rotates_and_old_refresh_reuse_revokes(client, clock):
    _login(client, "alice", "alice-pass")
    old_rt = client.cookies.get("sid_rt")

    # 第一次刷新：旧 rt 轮换
    assert client.post("/auth/refresh").status_code == 200
    # 窗口内并发重放旧 rt：成功，不误判
    clock.advance(0.1)
    client.cookies.set("sid_rt", old_rt)
    assert client.post("/auth/refresh").status_code == 200

    # 超出宽限窗口再次使用更老的 rt：复用 -> 撤销
    clock.advance(3)
    client.cookies.set("sid_rt", old_rt)
    reuse = client.post("/auth/refresh")
    assert reuse.status_code == 401
    assert reuse.json() == {"error": "token_reuse_detected"}

    # 家族撤销后，受保护入口同样返回 session_revoked
    me = client.get("/auth/me")
    assert me.status_code == 401
    assert me.json() == {"error": "session_revoked"}


# ------------------------------------------------------------------ 登出
def test_http_logout_idempotent_and_revokes(client):
    _login(client, "alice", "alice-pass")
    for _ in range(3):
        resp = client.post("/auth/logout")
        assert resp.status_code == 200  # 重复登出幂等
    # Cookie 被清除
    assert "sid_at" not in client.cookies

    # 手工塞回已撤销令牌 -> session_revoked，而不是匿名
    # 重新登录拿一对，再登出，再验证
    _login(client, "alice", "alice-pass")
    at = client.cookies.get("sid_at")
    rt = client.cookies.get("sid_rt")
    client.post("/auth/logout")
    client.cookies.set("sid_at", at)
    assert client.get("/auth/me").json() == {"error": "session_revoked"}
    client.cookies.set("sid_rt", rt)
    assert client.post("/auth/refresh").json() == {"error": "session_revoked"}


def test_logout_without_cookie_is_ok(client):
    client.cookies.clear()
    assert client.post("/auth/logout").status_code == 200


def test_logout_one_session_keeps_other(client):
    # 会话 A
    _login(client, "alice", "alice-pass")
    rt_a = client.cookies.get("sid_rt")
    at_a = client.cookies.get("sid_at")
    # 会话 B（同名 Cookie 被覆盖，先保存 A）
    _login(client, "admin", "admin-pass")
    at_b = client.cookies.get("sid_at")
    assert client.get("/auth/me").json()["username"] == "admin"

    # 登出 A 不影响 B
    client.cookies.set("sid_rt", rt_a)
    client.post("/auth/logout")
    client.cookies.set("sid_at", at_a)
    assert client.get("/auth/me").json() == {"error": "session_revoked"}

    client.cookies.set("sid_at", at_b)
    assert client.get("/auth/me").status_code == 200


# ------------------------------------------------------------ 信息泄露防护
def test_no_token_values_leak_in_logs(client, caplog):
    import logging

    _login(client, "alice", "alice-pass")
    at = client.cookies.get("sid_at")
    rt = client.cookies.get("sid_rt")
    client.post("/auth/refresh")
    client.get("/auth/me")
    client.post("/auth/logout")

    all_logs = "\n".join(r.getMessage() for r in caplog.records if r.name.startswith("auth"))
    assert at not in all_logs
    assert rt not in all_logs
    assert logging.getLogger("auth").name  # logger 存在


# ------------------------------------------------------------ 风险撤销入口
def test_risk_revoke_endpoint_kills_target_session(client):
    # alice 登录，拿到会话 id
    _login(client, "alice", "alice-pass")
    me = client.get("/auth/me").json()
    target_session = me["session_id"]
    at_alice = client.cookies.get("sid_at")
    rt_alice = client.cookies.get("sid_rt")

    # 非管理员无法调用风控接口
    denied = client.post(f"/admin/sessions/{target_session}/revoke")
    assert denied.status_code == 403

    # 管理员撤销 alice 的会话
    _login(client, "admin", "admin-pass")
    ok = client.post(f"/admin/sessions/{target_session}/revoke")
    assert ok.status_code == 200

    # alice 剩余凭证立即失效，原因可区分
    client.cookies.set("sid_at", at_alice)
    assert client.get("/auth/me").json() == {"error": "session_revoked"}
    client.cookies.set("sid_rt", rt_alice)
    assert client.post("/auth/refresh").json() == {"error": "session_revoked"}


def test_risk_revoke_requires_authentication(client):
    client.cookies.clear()
    resp = client.post("/admin/sessions/whatever/revoke")
    assert resp.status_code == 401
    assert resp.json() == {"error": "not_authenticated"}
