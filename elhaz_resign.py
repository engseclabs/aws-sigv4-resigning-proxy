"""
mitmproxy addon: validate inbound SigV4 requests signed with a proxy-issued
keypair, then re-sign and forward using elhaz IAC credentials.

Phase 1 — credential carrier + local validation:
  - Issues a unique fake (non-IAM) keypair per socket connection so each
    agent client has a distinct identity at the proxy.
  - Serves keypairs to agents over a Unix socket (creds.sock) so the AWS SDK
    can sign requests without holding real credentials.
  - Validates inbound SigV4 signatures locally, keyed by access_key_id.
  - Strips proxy auth headers and re-signs with the elhaz IAC session.

Usage:
    mitmdump --listen-port 8080 --scripts elhaz_resign.py

Config (env vars):
    ELHAZ_CONFIG_NAME   elhaz config name (default: sandbox-elhaz)
    ELHAZ_SOCKET_PATH   elhaz daemon socket path (default: elhaz's own default,
                        typically ~/.elhaz/sock/daemon.sock); set to
                        /tmp/elhaz.sock when running inside Docker
    PROXY_SOCK_PATH     Unix socket path for credential vending
                        (default: /run/proxy/creds.sock)
    PROXY_KEYPAIR_TTL   Keypair lifetime in seconds (default: 3600)
"""

__all__ = ["ElhazResignAddon", "CredentialStore", "parse_aws_host", "validate_sigv4"]

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import socket
import string
import subprocess
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator
from urllib.parse import parse_qs, urlparse

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from mitmproxy import http
from pydantic import BaseModel, ConfigDict

log = logging.getLogger(__name__)

ELHAZ_CONFIG = os.environ.get("ELHAZ_CONFIG_NAME", "sandbox-elhaz")
ELHAZ_SOCKET_PATH = os.environ.get("ELHAZ_SOCKET_PATH")  # None → elhaz uses its default
REFRESH_BEFORE_EXPIRY_SECONDS = 300

PROXY_SOCK_PATH = Path(os.environ.get("PROXY_SOCK_PATH", "/run/proxy/creds.sock"))
PROXY_KEYPAIR_TTL = int(os.environ.get("PROXY_KEYPAIR_TTL", "3600"))

# SigV4 access key IDs must start with AKIA and be 20 uppercase alphanumeric chars.
_AK_PREFIX = "AKIAPROXY"
_AK_ALPHABET = string.ascii_uppercase + string.digits


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #

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


def _error_status(exc: ProxyError) -> int:
    return _ERROR_STATUS.get(type(exc), 500)


# --------------------------------------------------------------------------- #
# Pydantic models
# --------------------------------------------------------------------------- #

class _BaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CredentialPayload(BaseModel):
    """Wire shape returned to the agent via creds.sock / credential_process."""
    Version: int = 1
    AccessKeyId: str
    SecretAccessKey: str
    Expiration: str  # ISO 8601


class _ErrorBody(_BaseModel):
    Code: str
    Message: str


class _ErrorEnvelope(_BaseModel):
    Error: _ErrorBody


# --------------------------------------------------------------------------- #
# Hostname → (service, region) parsing
# --------------------------------------------------------------------------- #

_AWS_HOST_PATTERNS = [
    (re.compile(r"^([a-z0-9-]+)\.([a-z]+-[a-z]+-\d+)\.amazonaws\.com$"), lambda m: (m.group(1), m.group(2))),
    (re.compile(r"^s3\.amazonaws\.com$"),          lambda m: ("s3",  "us-east-1")),
    (re.compile(r"^sts\.amazonaws\.com$"),         lambda m: ("sts", "us-east-1")),
    (re.compile(r"^([a-z0-9-]+)\.amazonaws\.com$"), lambda m: (m.group(1), "us-east-1")),
    (re.compile(r"^[^.]+\.s3\.amazonaws\.com$"),   lambda m: ("s3",  "us-east-1")),
    (re.compile(r"^[^.]+\.s3\.([a-z]+-[a-z]+-\d+)\.amazonaws\.com$"), lambda m: ("s3", m.group(1))),
]


def parse_aws_host(host: str) -> tuple[str, str] | None:
    """Return (service, region) from an AWS hostname, or None if not AWS."""
    host = host.lower().split(":")[0]
    if "amazonaws.com" not in host:
        return None
    for pattern, extractor in _AWS_HOST_PATTERNS:
        m = pattern.match(host)
        if m:
            return extractor(m)
    log.warning("Could not parse AWS host: %s", host)
    return None


# --------------------------------------------------------------------------- #
# Per-client credential store
# --------------------------------------------------------------------------- #

class _ClientCred(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_key_id: str
    secret_access_key: str
    prev_secret: str | None = None
    expiry: datetime

    def to_payload(self) -> CredentialPayload:
        return CredentialPayload(
            AccessKeyId=self.access_key_id,
            SecretAccessKey=self.secret_access_key,
            Expiration=self.expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )


def _new_access_key_id() -> str:
    suffix = "".join(secrets.choice(_AK_ALPHABET) for _ in range(20 - len(_AK_PREFIX)))
    return _AK_PREFIX + suffix


class CredentialStore:
    """Issues and tracks one unique keypair per socket connection."""

    def __init__(self) -> None:
        self._store: dict[str, _ClientCred] = {}
        self._lock = threading.Lock()

    def issue(self) -> _ClientCred:
        cred = _ClientCred(
            access_key_id=_new_access_key_id(),
            secret_access_key=secrets.token_hex(32),
            expiry=datetime.now(timezone.utc) + timedelta(seconds=PROXY_KEYPAIR_TTL),
        )
        with self._lock:
            self._store[cred.access_key_id] = cred
        log.info("Issued proxy keypair access_key_id=%s expiry=%s", cred.access_key_id, cred.expiry)
        return cred

    def valid_secrets_for(self, access_key_id: str) -> list[str] | None:
        """Return [current_secret, prev_secret?] for the given key, or None if unknown."""
        with self._lock:
            cred = self._store.get(access_key_id)
        if cred is None:
            return None
        return [cred.secret_access_key, *([cred.prev_secret] if cred.prev_secret else [])]


# --------------------------------------------------------------------------- #
# Unix socket credential server
# --------------------------------------------------------------------------- #

def _prepare_socket_path(sock_path: Path) -> None:
    """
    Remove a stale socket file if the path exists but no daemon is listening.
    Raises if a live server is already bound there.
    """
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    if not sock_path.exists():
        return
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(str(sock_path))
        probe.close()
        raise ProxyError(f"A server is already listening on {sock_path}")
    except ConnectionRefusedError:
        sock_path.unlink()
    except FileNotFoundError:
        pass
    finally:
        probe.close()


def _serve_creds(sock_path: Path, store: CredentialStore) -> None:
    """Issue a fresh keypair per connection and send it to the client (blocking)."""
    _prepare_socket_path(sock_path)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
        srv.bind(str(sock_path))
        sock_path.chmod(0o600)
        srv.listen()
        log.info("Credential socket listening at %s", sock_path)
        while True:
            try:
                conn, _ = srv.accept()
                with conn:
                    payload = store.issue().to_payload()
                    conn.sendall(payload.model_dump_json().encode())
            except Exception as exc:
                log.error("creds.sock error: %s", exc)


def start_creds_server(sock_path: Path, store: CredentialStore) -> None:
    t = threading.Thread(target=_serve_creds, args=(sock_path, store), daemon=True)
    t.start()


# --------------------------------------------------------------------------- #
# Local SigV4 validation
# --------------------------------------------------------------------------- #

def _hmac_sha256(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode(), hashlib.sha256).digest()


def _signing_key(secret: str, date_str: str, region: str, service: str) -> bytes:
    k = _hmac_sha256(("AWS4" + secret).encode(), date_str)
    k = _hmac_sha256(k, region)
    k = _hmac_sha256(k, service)
    return _hmac_sha256(k, "aws4_request")


def _parse_auth_header(auth: str) -> dict[str, str] | None:
    """Parse AWS4-HMAC-SHA256 Authorization header into component parts."""
    prefix = "AWS4-HMAC-SHA256 "
    if not auth.startswith(prefix):
        return None
    parts: dict[str, str] = {}
    for part in auth[len(prefix):].split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            parts[k.strip()] = v.strip()
    return parts if {"Credential", "SignedHeaders", "Signature"} <= parts.keys() else None


def validate_sigv4(flow: http.HTTPFlow, store: CredentialStore) -> bool:
    """
    Recompute the SigV4 signature for the inbound request and compare against
    the Authorization header. Looks up the signing secret by access_key_id so
    each client is validated against its own issued keypair.
    """
    auth = flow.request.headers.get("authorization", "")
    parsed = _parse_auth_header(auth)
    if not parsed:
        log.warning("Missing or malformed Authorization header")
        return False

    cred_parts = parsed["Credential"].split("/")
    if len(cred_parts) != 5:
        log.warning("Malformed Credential field: %s", parsed["Credential"])
        return False
    access_key_id, date_str, region, service, _ = cred_parts

    valid_secrets = store.valid_secrets_for(access_key_id)
    if valid_secrets is None:
        log.warning("Unknown access_key_id: %s", access_key_id)
        return False

    signed_headers = parsed["SignedHeaders"].split(";")
    received_sig = parsed["Signature"]

    canonical_headers = "".join(
        f"{h}:{flow.request.headers.get(h, '').strip()}\n"
        for h in signed_headers
    )
    body = flow.request.content or b""
    body_hash = hashlib.sha256(body).hexdigest()
    parsed_url = urlparse(flow.request.pretty_url)
    canonical_uri = parsed_url.path or "/"
    canonical_qs = "&".join(
        sorted(f"{k}={v}" for k, vs in parse_qs(parsed_url.query, keep_blank_values=True).items() for v in vs)
    )
    canonical_request = "\n".join([
        flow.request.method,
        canonical_uri,
        canonical_qs,
        canonical_headers,
        ";".join(signed_headers),
        body_hash,
    ])

    amz_date = flow.request.headers.get("x-amz-date", "")
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        f"{date_str}/{region}/{service}/aws4_request",
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    for secret in valid_secrets:
        key = _signing_key(secret, date_str, region, service)
        expected_sig = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected_sig, received_sig):
            log.info("Validated request from client access_key_id=%s", access_key_id)
            return True

    log.warning("SigV4 signature validation failed for access_key_id=%s", access_key_id)
    return False


# --------------------------------------------------------------------------- #
# Elhaz credential cache
# --------------------------------------------------------------------------- #

class ElhazCredentialCache:
    def __init__(self, config_name: str) -> None:
        self._config_name = config_name
        self._creds: Credentials | None = None
        self._expiry: datetime | None = None

    def _needs_refresh(self) -> bool:
        if self._creds is None or self._expiry is None:
            return True
        return (self._expiry - datetime.now(timezone.utc)).total_seconds() < REFRESH_BEFORE_EXPIRY_SECONDS

    def get(self) -> Credentials:
        if self._needs_refresh():
            self._refresh()
        return self._creds  # type: ignore[return-value]

    def _refresh(self) -> None:
        log.info("Fetching fresh credentials from elhaz (config=%s)", self._config_name)
        cmd = ["elhaz"]
        if ELHAZ_SOCKET_PATH:
            cmd += ["--socket-path", ELHAZ_SOCKET_PATH]
        cmd += ["export", "--format", "credential-process", "-n", self._config_name]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        self._creds = Credentials(
            access_key=data["AccessKeyId"],
            secret_key=data["SecretAccessKey"],
            token=data.get("SessionToken"),
        )
        expiry_str = data.get("Expiration")
        self._expiry = (
            datetime.fromisoformat(expiry_str.replace("Z", "+00:00")) if expiry_str else None
        )
        log.info("Credentials refreshed; expiry=%s", self._expiry)


# --------------------------------------------------------------------------- #
# mitmproxy addon
# --------------------------------------------------------------------------- #

_AUTH_HEADERS = {
    "authorization",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
}


def _aws_error_response(exc: ProxyError) -> http.Response:
    body = _ErrorEnvelope(
        Error=_ErrorBody(Code=exc.code, Message=str(exc))
    ).model_dump_json()
    return http.Response.make(
        _error_status(exc),
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
        SigV4Auth(creds, service, region).add_auth(aws_request)
        for key, value in aws_request.headers.items():
            flow.request.headers[key] = value

        log.info("Request re-signed for %s/%s", service, region)


def load(loader) -> None:  # noqa: D103 — mitmproxy hook
    pass


addons = [ElhazResignAddon()]
