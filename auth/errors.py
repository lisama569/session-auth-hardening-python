"""鉴权失败原因码与异常。

错误码面向调用方，稳定且可区分；错误响应中不携带任何令牌内容
或内部判定细节。详细判定依据只写入服务端日志。
"""

from enum import Enum


class AuthErrorCode(str, Enum):
    NOT_AUTHENTICATED = "not_authenticated"        # 未登录 / 没有凭证
    ACCESS_TOKEN_EXPIRED = "access_token_expired"  # 访问令牌过期
    REFRESH_TOKEN_EXPIRED = "refresh_token_expired"  # 刷新令牌过期
    SESSION_REVOKED = "session_revoked"            # 会话已撤销（登出/风险）
    TOKEN_REUSE_DETECTED = "token_reuse_detected"  # 刷新令牌复用（疑似泄露）
    INVALID_CREDENTIALS = "invalid_credentials"    # 登录凭据无效
    INVALID_TOKEN = "invalid_token"                # 令牌无法识别/篡改
    FORBIDDEN = "forbidden"                        # 已认证但权限不足
    RISK_REVOKED = "risk_revoked"                  # 风险判定导致撤销


class AuthError(Exception):
    """携带稳定错误码的鉴权异常。"""

    def __init__(self, code: AuthErrorCode, *, log_detail: str = "") -> None:
        super().__init__(code.value)
        self.code = code
        # 仅供服务端日志使用，绝不能进入响应体
        self.log_detail = log_detail


# 错误码 -> HTTP 状态码
HTTP_STATUS = {
    AuthErrorCode.NOT_AUTHENTICATED: 401,
    AuthErrorCode.ACCESS_TOKEN_EXPIRED: 401,
    AuthErrorCode.REFRESH_TOKEN_EXPIRED: 401,
    AuthErrorCode.SESSION_REVOKED: 401,
    AuthErrorCode.TOKEN_REUSE_DETECTED: 401,
    AuthErrorCode.INVALID_CREDENTIALS: 401,
    AuthErrorCode.INVALID_TOKEN: 401,
    AuthErrorCode.FORBIDDEN: 403,
    AuthErrorCode.RISK_REVOKED: 401,
}
