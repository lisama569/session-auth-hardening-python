"""FastAPI 依赖：从 Cookie 读取令牌、认证、RBAC 校验。

拒绝原因可区分：
* 未携带/无效/过期/撤销凭证 -> 401 + 对应错误码（由 require_principal 抛出）；
* 已认证但角色不足 -> 403 forbidden。
"""

from __future__ import annotations

import logging

from fastapi import Request

from auth.config import ACCESS_COOKIE
from auth.errors import AuthError, AuthErrorCode
from auth.models import Principal
from auth.service import AuthService

log = logging.getLogger("auth.deps")


def get_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def require_principal(request: Request) -> Principal:
    """要求已登录（认证），返回 Principal。"""
    service = get_service(request)
    raw = request.cookies.get(ACCESS_COOKIE)
    return service.authenticate_access_token(raw)


def require_roles(*roles: str):
    """要求当前主体拥有给定角色中的至少一个。

    未认证走 401（可区分的具体错误码）；已认证但权限不足走 403 forbidden。
    """
    required = frozenset(roles)

    def _dep(request: Request) -> Principal:
        principal = require_principal(request)
        if not (required & principal.roles):
            log.info(
                "rbac denied user=%s session=%s basis=missing_required_roles "
                "required=%s held=%s",
                principal.user_id,
                principal.session_id[:8],
                sorted(required),
                sorted(principal.roles),
            )
            raise AuthError(AuthErrorCode.FORBIDDEN)
        return principal

    return _dep
