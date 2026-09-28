"""受保护入口：任何登录用户可访问 /me；admin 角色可管理会话。

身份与权限是两道独立闸门：未登录拿到 401 系列可区分错误码，
已登录但角色不足拿到 403 permission_denied。
"""

from fastapi import APIRouter, Depends

from app.deps import get_auth_service, require_roles
from app.models import AccessRecord, Role, WhoamiResponse

router = APIRouter(tags=["protected"])


@router.get("/me")
def me(
    access: AccessRecord = Depends(require_roles()),
    service=Depends(get_auth_service),
) -> WhoamiResponse:
    user = service.user_for(access.username)
    return WhoamiResponse(
        username=access.username,
        roles=list(user.roles),
        session_id=access.session_id,
    )


@router.get("/admin/sessions")
def admin_sessions(
    access: AccessRecord = Depends(require_roles(Role.ADMIN)),
    service=Depends(get_auth_service),
):
    """列出管理员指定视角下当前调用者可见的会话（演示：列出自己的会话）。"""
    sessions = service.list_sessions(access.username)
    return {
        "sessions": [
            {
                "id": s.id,
                "username": s.username,
                "created_at": s.created_at.isoformat(),
                "revoked": s.revoked,
                "revoke_reason": s.revoke_reason,
            }
            for s in sessions
        ]
    }


@router.post("/admin/sessions/{session_id}/revoke")
def admin_revoke_session(
    session_id: str,
    access: AccessRecord = Depends(require_roles(Role.ADMIN)),
    service=Depends(get_auth_service),
):
    """风控/管理员入口：判定会话有风险时立即撤销其全部剩余凭证。"""
    ok = service.revoke_session_by_admin(session_id)
    return {"result": "ok", "revoked": ok}
