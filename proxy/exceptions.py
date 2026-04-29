"""Exception hierarchy for the elhaz-resign proxy."""

__all__ = ["ProxyError", "ValidationError", "UpstreamError", "error_status"]


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


_ERROR_STATUS: dict[type[ProxyError], int] = {
    ValidationError: 403,
    UpstreamError: 503,
}


def error_status(exc: ProxyError) -> int:
    return _ERROR_STATUS.get(type(exc), 500)
