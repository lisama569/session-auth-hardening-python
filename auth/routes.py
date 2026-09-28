"""HTTP 入口：登录/登出/刷新，以及鉴权演示接口。

令牌只通过 HttpOnly Cookie 下发，响应体不回传令牌，前端 JS 无法读取，
降低 XSS 窃取风险。
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel

from auth.config import (
    ACCESS_COOKIE,
    REFRESH_COOKIE,
)
from auth.deps import get_service, require_principal, require_roles
from auth.models import Principal
from auth.service import AuthService

log = logging.getLogger("auth.routes")

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str



def _set_cookies(response: Response, access: str, refresh: str, service: AuthService) -> None:
    cfg = service.config
    response.set_cookie(
        ACCESS_COOKIE,
        access,
        httponly=True,
        secure=cfg.cookie_secure,
        samesite=cfg.cookie_samesite,
        path=cfg.cookie_path,
        max_age=cfg.access_token_ttl,
    )
    response.set_cookie(
        REFRESH_COOKIE,
        refresh,
        httponly=True,
        secure=cfg.cookie_secure,
        samesite=cfg.cookie_samesite,
        path=cfg.cookie_path,
        max_age=cfg.refresh_token_ttl,
    )


def _clear_cookies(response: Response, service: AuthService) -> None:
    response.delete_cookie(ACCESS_COOKIE, path=service.config.cookie_path)
    response.delete_cookie(REFRESH_COOKIE, path=service.config.cookie_path)


@router.post("/auth/login")
def login_endpoint(
    body: LoginRequest,
    request: Request,
    response: Response,
    service: AuthService = Depends(get_service),
):
    log.info("http login attempt input_user=%s", body.username)
    _session, access, refresh = service.login(body.username, body.password)
    _set_cookies(response, access, refresh, service)
    return {"status": "ok"}


@router.post("/auth/logout")
def logout_endpoint(
    request: Request,
    response: Response,
    service: AuthService = Depends(get_service),
):
    # 幂等：任何情况都清除本地 Cookie 并返回 200
    refresh = request.cookies.get(REFRESH_COOKIE)
    service.logout(refresh)
    _clear_cookies(response, service)
    return {"status": "ok"}


@router.post("/auth/refresh")
def refresh_endpoint(
    request: Request,
    response: Response,
    service: AuthService = Depends(get_service),
):
    refresh = request.cookies.get(REFRESH_COOKIE)
    _session, access, new_refresh = service.rotate_refresh_token(refresh)
    _set_cookies(response, access, new_refresh, service)
    return {"status": "ok"}


@router.get("/auth/me")
def me_endpoint(principal: Principal = Depends(require_principal)):
    return {
        "user_id": principal.user_id,
        "username": principal.username,
        "roles": sorted(principal.roles),
        "session_id": principal.session_id,
    }


@router.get("/admin/users")
def admin_endpoint(principal: Principal = Depends(require_roles("admin"))):
    return {"result": "admin-only data", "for": principal.username}


@router.get("/member/area")
def member_endpoint(principal: Principal = Depends(require_roles("member"))):
    return {"result": "member area", "for": principal.username}


@router.post("/admin/sessions/{session_id}/revoke")
def revoke_session_endpoint(
    session_id: str,
    service: AuthService = Depends(get_service),
    principal: Principal = Depends(require_roles("admin")),
):
    """风控/管理员：按会话 id 立即撤销整条会话。幂等。"""
    service.revoke_session(session_id, reason="administrative_risk")
    return {"status": "ok"}
