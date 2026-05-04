"""proxy.py plugin: intercepts AWS requests, validates SigV4, re-signs with real credentials."""

__all__ = ["ResignPlugin"]

import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from botocore.auth import S3SigV4Auth, SigV4Auth
from botocore.awsrequest import AWSRequest
from proxy.http.exception import HttpRequestRejected
from proxy.http.parser import HttpParser
from proxy.http.proxy.plugin import HttpProxyBasePlugin

from .allowlist import Allowlist
from .credentials import CredentialStore, start_creds_server
from .exceptions import EnforcementError, ProxyError, UpstreamError, ValidationError, error_status
from .models import ErrorEnvelope
from .resolver import load_resolver
from .sigv4 import parse_aws_host, validate_sigv4
from .upstream_creds import BotoCredentialSource

log = logging.getLogger(__name__)

PROXY_SOCK_PATH = Path(os.environ.get("PROXY_SOCK_PATH", "/run/proxy/creds.sock"))

_PROXY_MODE = os.environ.get("PROXY_MODE", "record").lower()
_ALLOWLIST_PATH = os.environ.get("ALLOWLIST_PATH", "")
_ACTION_LOG_PATH = Path(
    os.environ.get("ACTION_LOG_PATH", str(Path.home() / ".iam-agent-proxy" / "actions.log"))
)

_log_lock = threading.Lock()

_AUTH_HEADERS = {
    b"authorization",
    b"x-amz-date",
    b"x-amz-security-token",
    b"x-amz-content-sha256",
}


def _load_allowlist() -> Allowlist | None:
    if _PROXY_MODE != "enforce":
        return None
    if not _ALLOWLIST_PATH:
        raise RuntimeError("PROXY_MODE=enforce requires ALLOWLIST_PATH to be set")
    path = Path(_ALLOWLIST_PATH)
    if not path.exists():
        raise RuntimeError(f"ALLOWLIST_PATH {path} does not exist")
    log.info("Enforcement mode: loading allowlist from %s", path)
    return Allowlist.from_file(path)


def _emit_actions(actions: list[str], service: str, method: str, path: str, blocked: bool) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    status = "BLOCKED" if blocked else "ALLOWED"
    for action in actions:
        line = f"[{ts}] {status:7s}  {action}"
        print(line, flush=True)
        try:
            _ACTION_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with _log_lock:
                with open(_ACTION_LOG_PATH, "a") as f:
                    f.write(action + "\n")
        except OSError:
            pass


# Module-level singletons shared across plugin instances (one per worker thread).
_store: CredentialStore | None = None
_upstream_creds: BotoCredentialSource | None = None
_allowlist: Allowlist | None = None
_resolver = None
_init_lock = threading.Lock()


def _ensure_initialized() -> None:
    global _store, _upstream_creds, _allowlist, _resolver
    if _store is not None:
        return
    with _init_lock:
        if _store is not None:
            return
        _store = CredentialStore()
        _upstream_creds = BotoCredentialSource()
        _allowlist = _load_allowlist()
        _resolver = load_resolver()
        start_creds_server(PROXY_SOCK_PATH, _store)
        log.info("Proxy mode: %s", _PROXY_MODE)
        log.info("Action log: %s", _ACTION_LOG_PATH)


def _make_reject(exc: ProxyError) -> HttpRequestRejected:
    status = error_status(exc)
    body = ErrorEnvelope.from_exc(exc.code, str(exc)).model_dump_json().encode()
    return HttpRequestRejected(
        status_code=status,
        reason=str(exc).encode(),
        headers={
            b"Content-Type": b"application/json",
            b"Content-Length": str(len(body)).encode(),
            b"Connection": b"close",
        },
        body=body,
    )


def _headers_dict(request: HttpParser) -> dict[str, str]:
    """Extract headers as a plain str→str dict (lowercased keys)."""
    if not request.headers:
        return {}
    return {
        k.decode(): v[1].decode()
        for k, v in request.headers.items()
    }


class ResignPlugin(HttpProxyBasePlugin):
    """proxy.py plugin that validates and re-signs AWS SigV4 requests."""

    def handle_client_request(self, request: HttpParser) -> HttpParser | None:
        _ensure_initialized()

        host_bytes = request.host or b""
        host = host_bytes.decode()
        parsed = parse_aws_host(host)
        if parsed is None:
            return request

        service, region = parsed
        log.info(
            "Intercepted AWS request: host=%s service=%s region=%s method=%s",
            host, service, region, (request.method or b"").decode(),
        )

        try:
            return self._handle(request, service, region)
        except ProxyError as exc:
            log.warning("Rejected request: %s", exc)
            raise _make_reject(exc) from exc

    def _handle(self, request: HttpParser, service: str, region: str) -> HttpParser:
        method = (request.method or b"GET").decode()
        path = (request.path or b"/").decode()
        host = (request.host or b"").decode()
        headers = _headers_dict(request)
        body = request.body or b""

        url = f"https://{host}{path}"

        if not validate_sigv4(method, url, headers, body, _store):
            raise ValidationError("The security token included in the request is invalid.")

        actions = _resolver.resolve(
            method=method,
            host=host,
            path=path,
            headers=headers,
            body=body,
            service_slug=service,
        )

        if _allowlist is not None:
            if not _allowlist.permits(actions):
                denied = actions[0] if actions else f"{service}:Unknown"
                _emit_actions(actions, service, method, path, blocked=True)
                raise EnforcementError(
                    f"User is not authorized to perform: {denied} "
                    f"(proxy enforcement mode)"
                )

        if actions:
            _emit_actions(actions, service, method, path, blocked=False)

        # Strip inbound auth headers
        for h in _AUTH_HEADERS:
            request.del_header(h)

        try:
            creds = _upstream_creds.get()
        except Exception as exc:
            raise UpstreamError("Proxy could not obtain IAC credentials.") from exc

        # Rebuild headers dict after stripping for re-signing
        clean_headers = _headers_dict(request)
        aws_request = AWSRequest(
            method=method,
            url=url,
            data=body,
            headers=clean_headers,
        )
        auth_cls = S3SigV4Auth if service == "s3" else SigV4Auth
        auth_cls(creds, service, region).add_auth(aws_request)

        # Write the new auth headers back onto the proxy.py request
        for key, value in aws_request.headers.items():
            request.add_header(key.encode(), value.encode())

        log.info("Request re-signed for %s/%s", service, region)
        return request
