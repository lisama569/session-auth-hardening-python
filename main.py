"""应用入口：组装认证服务、路由、统一错误处理。"""

from __future__ import annotations

import logging

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from auth.errors import HTTP_STATUS, AuthError
from auth.models import User
from auth.routes import router as auth_router
from auth.security import hash_password
from auth.service import AuthService
from auth.store import AuthStore

logging.basicConfig(level=logging.INFO)


def create_app() -> FastAPI:
    app = FastAPI(title="session-auth-hardening")
    store = AuthStore()
    _seed_users(store)
    app.state.auth_service = AuthService(store)

    app.include_router(auth_router)

    @app.exception_handler(AuthError)
    async def handle_auth_error(request: Request, exc: AuthError):
        # 响应体只包含稳定错误码，不含令牌或内部细节
        return JSONResponse(
            status_code=HTTP_STATUS[exc.code],
            content={"error": exc.code.value},
        )

    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    return app


def _seed_users(store: AuthStore) -> None:
    # 演示用户：普通成员与管理员
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


app = create_app()


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
