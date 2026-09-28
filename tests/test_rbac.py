"""身份认证与基于角色的访问控制：401 与 403 必须可区分。"""


def test_anonymous_access_is_401_missing(env):
    r = env.client.get("/me")
    env.assert_decision("匿名访问 /me", r, 401, "access_token_missing")

    r = env.client.get("/admin/sessions")
    env.assert_decision("匿名访问管理入口", r, 401, "access_token_missing")


def test_login_success_and_whoami(env):
    r, access, refresh = env.login("alice", "alice123")
    assert r.status_code == 200
    assert access and refresh
    me = env.client.get("/me", headers=env.bearer(access))
    assert me.status_code == 200
    assert me.json()["username"] == "alice"
    assert me.json()["roles"] == ["member"]


def test_login_wrong_password_is_distinguishable(env):
    r = env.client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    env.assert_decision("错误密码登录", r, 401, "invalid_credentials")

    r = env.client.post("/auth/login", json={"username": "ghost", "password": "x"})
    env.assert_decision("不存在用户登录", r, 401, "invalid_credentials")


def test_member_authenticated_but_forbidden_from_admin(env):
    _, access, _ = env.login("alice", "alice123")
    r = env.client.get("/admin/sessions", headers=env.bearer(access))
    env.assert_decision("成员访问管理入口（已登录、无权限）", r, 403, "permission_denied")


def test_admin_can_access_admin_entrypoint(env):
    _, access, _ = env.login("admin", "admin123")
    r = env.client.get("/admin/sessions", headers=env.bearer(access))
    assert r.status_code == 200
    assert isinstance(r.json()["sessions"], list)


def test_garbage_access_token_is_invalid_not_missing(env):
    r = env.client.get("/me", headers=env.bearer("totally-bogus-token"))
    env.assert_decision("无法识别的访问令牌", r, 401, "access_token_invalid",
                        secret="totally-bogus-token")


def test_cookie_based_access_works(env):
    env.login("alice", "alice123")  # TestClient 自动保存并回传 Cookie
    r = env.client.get("/me")
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


def test_error_messages_never_leak_token(env, caplog):
    _, access, _ = env.login("alice", "alice123")
    r = env.client.get("/me", headers=env.bearer(access + "x"))
    body = env.assert_decision("被篡改的访问令牌", r, 401, "access_token_invalid",
                               secret=access)
    # 对外信息通用化
    assert body["error"]["message"] in {"访问令牌无效"}
    # 审计日志只出现令牌哈希短指纹，不出现原文
    assert access not in caplog.text
