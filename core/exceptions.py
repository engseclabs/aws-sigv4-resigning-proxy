"""Exception hierarchy for the iam-agent-proxy."""

__all__ = ["ProxyError", "ValidationError", "UpstreamError", "EnforcementError", "error_status"]


class ProxyError(Exception):
    def __init__(self, message: str, *, code: str = "InternalError") -> None:
        super().__init__(message)
        self.code = code


class ValidationError(ProxyError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="InvalidClientTokenId")


class UpstreamError(ProxyError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="ServiceUnavailable")


class EnforcementError(ProxyError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="AccessDenied")


_ERROR_STATUS: dict[type[ProxyError], int] = {
    ValidationError: 403,
    UpstreamError: 503,
    EnforcementError: 403,
}


def error_status(exc: ProxyError) -> int:
    return _ERROR_STATUS.get(type(exc), 500)
