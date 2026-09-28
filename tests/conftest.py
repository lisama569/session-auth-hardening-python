"""pytest 夹具：短时效配置、可控时钟、HTTP 客户端与判定断言助手。"""

import logging

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.models import UserRecord
from main import create_app

TEST_SETTINGS = Settings(
    access_token_ttl_seconds=2,
    refresh_token_ttl_seconds=60,
    refresh_grace_window_seconds=1,
    users=(
        UserRecord("admin", "admin123", ("admin", "member")),
        UserRecord("alice", "alice123", ("member",)),
        UserRecord("bob", "bob123", ("member",)),
    ),
)


@pytest.fixture
def env():
    """组装应用、时钟与服务，并暴露测试辅助方法。"""
    app = create_app(settings=TEST_SETTINGS)
    clock = app.state.auth_clock
    service = app.state.auth_service

    class Env:
        def __init__(self):
            self.app = app
            self.clock = clock
            self.service = service
            self.client = TestClient(app)
            self.settings = TEST_SETTINGS

        def login(self, username, password):
            """返回 (响应, 访问令牌, 刷新令牌)，令牌从 Set-Cookie 中取出。"""
            resp = self.client.post(
                "/auth/login", json={"username": username, "password": password}
            )
            access = resp.cookies.get("access_token")
            refresh = resp.cookies.get("refresh_token")
            return resp, access, refresh

        def bearer(self, token):
            return {"Authorization": f"Bearer {token}"}

        def raw_cookie(self, access=None, refresh=None):
            parts = []
            if access is not None:
                parts.append(f"access_token={access}")
            if refresh is not None:
                parts.append(f"refresh_token={refresh}")
            return {"Cookie": "; ".join(parts)}

        def assert_decision(self, description, response, status, code, secret=None):
            """断言判定结果，并在测试日志中打印输入与判定依据。"""
            body = response.json()
            print(
                f"\n[case] {description}\n"
                f"  input   : {response.request.method} {response.request.url.path}\n"
                f"  expect  : HTTP {status} / {code}\n"
                f"  actual  : HTTP {response.status_code} / "
                f"{body.get('error', {}).get('code') if isinstance(body, dict) else body}\n"
                f"  message : {body.get('error', {}).get('message') if isinstance(body, dict) else ''}"
            )
            assert response.status_code == status, f"{description}: status={response.status_code}"
            assert body["error"]["code"] == code, f"{description}: body={body}"
            # 任何错误体都不得泄露令牌原文
            if secret:
                assert secret not in response.text, "响应中泄露了令牌原文"
            return body

    return Env()


@pytest.fixture(autouse=True)
def _capture_auth_logs(caplog):
    """让每个用例都能断言/查看 auth 审计日志（含判定依据 reason）。"""
    caplog.set_level(logging.INFO, logger="app.auth")
    yield
