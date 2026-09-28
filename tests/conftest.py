"""pytest 公共夹具：可控时钟的服务与 FastAPI TestClient。"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from auth.config import AuthConfig
from auth.models import User
from auth.security import hash_password
from auth.service import AuthService
from auth.store import AuthStore
from main import create_app


class FakeClock:
    """从真实时间起步、可显式快进的时钟。"""

    def __init__(self) -> None:
        import time

        self.t = time.time()

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def auth_config() -> AuthConfig:
    # 短 TTL + 明确宽限窗口，便于确定性地验证过期与复用
    return AuthConfig(
        access_token_ttl=10,
        refresh_token_ttl=60,
        rotation_grace_seconds=2,
        idle_timeout_seconds=120,
    )


@pytest.fixture
def service(clock: FakeClock, auth_config: AuthConfig) -> AuthService:
    store = AuthStore()
    _seed(store)
    return AuthService(store, config=auth_config, clock=clock)


@pytest.fixture
def client(clock: FakeClock, auth_config: AuthConfig) -> TestClient:
    app = create_app()
    store = AuthStore()
    _seed(store)
    # 替换 create_app 默认服务为可控时钟/短 TTL 的服务
    app.state.auth_service = AuthService(store, config=auth_config, clock=clock)
    return TestClient(app)


def _seed(store: AuthStore) -> None:
    store.upsert_user(
        User(
            id="u-admin",
            username="admin",
            password_sha256=hash_password("admin-pass"),
            roles=frozenset({"admin", "member"}),
        )
    )
    store.upsert_user(
        User(
            id="u-alice",
            username="alice",
            password_sha256=hash_password("alice-pass"),
            roles=frozenset({"member"}),
        )
    )


@pytest.fixture(autouse=True)
def _decision_logging(caplog: pytest.LogCaptureFixture):
    """保证每个用例都能在 -rP / --log-cli-level=INFO 下看到输入与判定依据。"""
    caplog.set_level(logging.INFO, logger="auth")
    yield
