"""FastAPI 依赖：从 Cookie/Header 提取凭证并完成身份+权限校验。

拒绝原因分层：
- 身份层失败（未携带/无效/过期/已撤销）-> 401，错误码可区分；
- 已通过身份校验但缺少所需角色 -> 403 permission_denied。
"""

from collections.abc import Callable

from fastapi import Depends, Request

from app.config import get_settings
from app.errors import AuthError, ErrorCode
from app.models import AccessRecord, Role
from app.service import AuthService, Clock
from app.store import TokenStore

ACCESS_COOKIE = "access_token"
REFRESH_COOKIE = "refresh_token"


def get_auth_service(request: Request) -> AuthService:
    """返回挂在 app.state 上的单例服务；未挂载时惰性创建一个默认实例。"""
    service = getattr(request.app.state, "auth_service", None)
    if service is None:
        settings = get_settings()
        service = AuthService(TokenStore(list(settings.users)), settings, Clock())
        request.app.state.auth_service = service
    return service


def _extract_access_token(request: Request) -> str | None:
    """优先读取 Authorization: Bearer，再回退到 HttpOnly Cookie。"""
    auth = request.headers.get("authorization")
    if auth:
        scheme, _, value = auth.partition(" ")
        if scheme.lower() == "bearer" and value.strip():
            return value.strip()
    token = request.cookies.get(ACCESS_COOKIE)
    return token if token else None


def require_roles(*roles: Role) -> Callable:
    """依赖工厂：任何已登录用户用 require_roles()；需要特定角色则传入角色。"""
    required = set(roles)

    def dependency(
        request: Request,
        service: AuthService = Depends(get_auth_service),
    ) -> AccessRecord:
        access = service.authenticate_access(_extract_access_token(request))
        if required:
            user = service.user_for(access.username)
            if not required.intersection(user.roles):
                raise AuthError(
                    ErrorCode.PERMISSION_DENIED,
                    "无权访问该资源",
                    status_code=403,
                )
        return access

    return dependency
