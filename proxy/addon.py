"""mitmproxy addon: the ElhazResignAddon entry point."""

__all__ = ["ElhazResignAddon", "load", "addons"]

import logging
import os
from pathlib import Path

from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest
from mitmproxy import http

from .credentials import CredentialStore, start_creds_server
from .elhaz import ELHAZ_CONFIG, ElhazCredentialCache
from .exceptions import ProxyError, UpstreamError, ValidationError, error_status
from .models import ErrorEnvelope
from .sigv4 import parse_aws_host, validate_sigv4

log = logging.getLogger(__name__)

PROXY_SOCK_PATH = Path(os.environ.get("PROXY_SOCK_PATH", "/run/proxy/creds.sock"))

_AUTH_HEADERS = {
    "authorization",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
}


def _aws_error_response(exc: ProxyError) -> http.Response:
    body = ErrorEnvelope.from_exc(exc.code, str(exc)).model_dump_json()
    return http.Response.make(
        error_status(exc),
        body,
        {"Content-Type": "application/json"},
    )


class ElhazResignAddon:
    def __init__(self) -> None:
        self.store = CredentialStore()
        self.elhaz = ElhazCredentialCache(ELHAZ_CONFIG)
        start_creds_server(PROXY_SOCK_PATH, self.store)

    def request(self, flow: http.HTTPFlow) -> None:
        parsed = parse_aws_host(flow.request.pretty_host)
        if parsed is None:
            return

        service, region = parsed
        log.info(
            "Intercepted AWS request: host=%s service=%s region=%s method=%s",
            flow.request.pretty_host, service, region, flow.request.method,
        )

        try:
            self._handle(flow, service, region)
        except ProxyError as exc:
            log.warning("Rejected request: %s", exc)
            flow.response = _aws_error_response(exc)

    def _handle(self, flow: http.HTTPFlow, service: str, region: str) -> None:
        if not validate_sigv4(flow, self.store):
            raise ValidationError("The security token included in the request is invalid.")

        for h in list(flow.request.headers.keys()):
            if h.lower() in _AUTH_HEADERS:
                del flow.request.headers[h]

        try:
            creds = self.elhaz.get()
        except Exception as exc:
            raise UpstreamError("Proxy could not obtain IAC credentials.") from exc

        aws_request = AWSRequest(
            method=flow.request.method,
            url=flow.request.pretty_url,
            data=flow.request.content or b"",
            headers=dict(flow.request.headers),
        )
        auth_cls = S3SigV4Auth if service == "s3" else SigV4Auth
        auth_cls(creds, service, region).add_auth(aws_request)
        for key, value in aws_request.headers.items():
            flow.request.headers[key] = value

        log.info("Request re-signed for %s/%s", service, region)


def load(loader) -> None:  # noqa: D103 — mitmproxy hook
    pass


addons = [ElhazResignAddon()]
