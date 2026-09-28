"""认证入口：登录、刷新、登出。

Cookie 策略：access_token / refresh_token 均为 HttpOnly（JS 不可读）、
SameSite=Lax；生产环境通过 COOKIE_SECURE=1 开启 Secure。
错误响应只包含稳定错误码与通用提示，不回显任何令牌内容或内部判定细节。
"""

import logging

from fastapi import APIRouter, Depends, Request, Response

from app.config import Settings
from app.deps import ACCESS_COOKIE, REFRESH_COOKIE, get_auth_service
from app.errors import AuthError, ErrorCode
from app.models import LoginRequest
from app.service import AuthService, IssuedTokens

logger = logging.getLogger("app.auth.http")

router = APIRouter(tags=["auth"])


def _set_token_cookies(response: Response, issued: IssuedTokens, settings: Settings) -> None:
    response.set_cookie(
        key=ACCESS_COOKIE,
        value=issued.access_token,
        max_age=settings.access_token_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path=settings.cookie_path,
    )
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=issued.refresh_token,
        max_age=settings.refresh_token_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path=settings.cookie_path,
    )


def _clear_token_cookies(response: Response, settings: Settings) -> None:
    response.delete_cookie(ACCESS_COOKIE, path=settings.cookie_path)
    response.delete_cookie(REFRESH_COOKIE, path=settings.cookie_path)


@router.post("/auth/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    service: AuthService = Depends(get_auth_service),
):
    settings = service.settings
    issued = service.login(payload.username, payload.password)
    _set_token_cookies(response, issued, settings)
    logger.info("http event=login endpoint=/auth/login user=%s result=allow", payload.username)
    return {
        "result": "ok",
        "session_id": issued.session.id,
        "roles": list(service.user_for(issued.session.username).roles),
    }


@router.post("/auth/refresh")
def refresh(
    request: Request,
    response: Response,
    service: AuthService = Depends(get_auth_service),
):
    settings = service.settings
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        # 同时兼容客户端通过 Bearer 提交刷新令牌的情况
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    if not token:
        raise AuthError(ErrorCode.REFRESH_TOKEN_MISSING, "未提供刷新令牌", 401)

    issued = service.refresh(token)
    _set_token_cookies(response, issued, settings)
    return {"result": "ok", "session_id": issued.session.id}


@router.post("/auth/logout")
def logout(
    request: Request,
    response: Response,
    service: AuthService = Depends(get_auth_service),
):
    # 始终幂等成功：无论有无令牌、令牌是否有效，都清除 Cookie，且只影响本条会话
    token = request.cookies.get(REFRESH_COOKIE)
    service.logout(token)
    _clear_token_cookies(response, service.settings)
    return {"result": "ok"}
