"""应用入口：组装依赖并注册统一的鉴权错误处理。"""

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.errors import AuthError
from app.routes_auth import router as auth_router
from app.routes_protected import router as protected_router
from app.service import AuthService, Clock
from app.store import TokenStore


def build_service(settings: Settings | None = None, clock: Clock | None = None) -> tuple[AuthService, Clock]:
    settings = settings or get_settings()
    clock = clock or Clock()
    return AuthService(TokenStore(list(settings.users)), settings, clock), clock


def create_app(settings: Settings | None = None, clock: Clock | None = None) -> FastAPI:
    app = FastAPI(title="session-auth-hardening")
    service, clock = build_service(settings, clock)
    app.state.auth_service = service
    app.state.auth_clock = clock
    app.include_router(auth_router)
    app.include_router(protected_router)

    @app.exception_handler(AuthError)
    async def handle_auth_error(request: Request, exc: AuthError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code.value, "message": exc.message}},
        )

    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
