"""可区分、可解释且不泄露敏感信息的鉴权拒绝原因。"""

from enum import Enum


class ErrorCode(str, Enum):
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCESS_TOKEN_MISSING = "access_token_missing"
    ACCESS_TOKEN_EXPIRED = "access_token_expired"
    ACCESS_TOKEN_REVOKED = "access_token_revoked"
    ACCESS_TOKEN_INVALID = "access_token_invalid"
    REFRESH_TOKEN_MISSING = "refresh_token_missing"
    REFRESH_TOKEN_EXPIRED = "refresh_token_expired"
    REFRESH_TOKEN_REVOKED = "refresh_token_revoked"
    REFRESH_TOKEN_INVALID = "refresh_token_invalid"
    REFRESH_TOKEN_REUSED = "refresh_token_reused"
    SESSION_REVOKED = "session_revoked"
    PERMISSION_DENIED = "permission_denied"


class AuthError(Exception):
    """鉴权失败：携带稳定的机器可读错误码与对外安全信息。"""

    def __init__(self, code: ErrorCode, message: str, status_code: int = 401):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
