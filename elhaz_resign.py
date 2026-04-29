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

import dataclasses
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
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from mitmproxy import http

log = logging.getLogger(__name__)

ELHAZ_CONFIG = os.environ.get("ELHAZ_CONFIG_NAME", "sandbox-elhaz")
ELHAZ_SOCKET_PATH = os.environ.get("ELHAZ_SOCKET_PATH")  # None → elhaz uses its default
REFRESH_BEFORE_EXPIRY_SECONDS = 300

PROXY_SOCK_PATH = os.environ.get("PROXY_SOCK_PATH", "/run/proxy/creds.sock")
PROXY_KEYPAIR_TTL = int(os.environ.get("PROXY_KEYPAIR_TTL", "3600"))

# SigV4 access key IDs must start with AKIA and be 20 uppercase alphanumeric chars.
_AK_PREFIX = "AKIAPROXY"
_AK_ALPHABET = string.ascii_uppercase + string.digits


# --------------------------------------------------------------------------- #
# Hostname → (service, region) parsing
# --------------------------------------------------------------------------- #

_AWS_HOST_PATTERNS = [
    (re.compile(r"^([a-z0-9-]+)\.([a-z]+-[a-z]+-\d+)\.amazonaws\.com$"), lambda m: (m.group(1), m.group(2))),
    (re.compile(r"^s3\.amazonaws\.com$"), lambda m: ("s3", "us-east-1")),
    (re.compile(r"^sts\.amazonaws\.com$"), lambda m: ("sts", "us-east-1")),
    (re.compile(r"^([a-z0-9-]+)\.amazonaws\.com$"), lambda m: (m.group(1), "us-east-1")),
    (re.compile(r"^[^.]+\.s3\.amazonaws\.com$"), lambda m: ("s3", "us-east-1")),
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

@dataclasses.dataclass
class _ClientCred:
    access_key_id: str
    secret_access_key: str
    prev_secret: str | None
    expiry: datetime


def _new_access_key_id() -> str:
    suffix = "".join(secrets.choice(_AK_ALPHABET) for _ in range(20 - len(_AK_PREFIX)))
    return _AK_PREFIX + suffix


class CredentialStore:
    """
    Issues and tracks one unique keypair per socket connection.
    Each call to issue() returns a new keypair and registers it so that
    validate() can look up the secret by access_key_id.
    """

    def __init__(self) -> None:
        self._store: dict[str, _ClientCred] = {}
        self._lock = threading.Lock()

    def issue(self) -> _ClientCred:
        access_key_id = _new_access_key_id()
        secret = secrets.token_hex(32)
        expiry = datetime.now(timezone.utc) + timedelta(seconds=PROXY_KEYPAIR_TTL)
        cred = _ClientCred(
            access_key_id=access_key_id,
            secret_access_key=secret,
            prev_secret=None,
            expiry=expiry,
        )
        with self._lock:
            self._store[access_key_id] = cred
        log.info("Issued proxy keypair access_key_id=%s expiry=%s", access_key_id, expiry)
        return cred

    def valid_secrets_for(self, access_key_id: str) -> list[str] | None:
        """Return [current_secret, prev_secret?] for the given key, or None if unknown."""
        with self._lock:
            cred = self._store.get(access_key_id)
        if cred is None:
            return None
        result = [cred.secret_access_key]
        if cred.prev_secret:
            result.append(cred.prev_secret)
        return result

    def credential_json(self, cred: _ClientCred) -> bytes:
        payload = {
            "Version": 1,
            "AccessKeyId": cred.access_key_id,
            "SecretAccessKey": cred.secret_access_key,
            "Expiration": cred.expiry.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        return json.dumps(payload).encode()


# --------------------------------------------------------------------------- #
# Unix socket credential server
# --------------------------------------------------------------------------- #

def _serve_creds(sock_path: str, store: CredentialStore) -> None:
    """Issue a fresh keypair per connection and send it to the client (blocking)."""
    sock_dir = os.path.dirname(sock_path)
    if sock_dir:
        os.makedirs(sock_dir, exist_ok=True)
    if os.path.exists(sock_path):
        os.unlink(sock_path)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
        srv.bind(sock_path)
        os.chmod(sock_path, 0o600)
        srv.listen()
        log.info("Credential socket listening at %s", sock_path)
        while True:
            try:
                conn, _ = srv.accept()
                with conn:
                    cred = store.issue()
                    conn.sendall(store.credential_json(cred))
            except Exception as exc:
                log.error("creds.sock error: %s", exc)


def start_creds_server(sock_path: str, store: CredentialStore) -> None:
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
    parts = {}
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

    # Credential field: <access_key>/<date>/<region>/<service>/aws4_request
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

    canonical_headers = ""
    for h in signed_headers:
        canonical_headers += h + ":" + flow.request.headers.get(h, "").strip() + "\n"

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
        self.config_name = config_name
        self._creds: Credentials | None = None
        self._expiry: datetime | None = None

    def _needs_refresh(self) -> bool:
        if self._creds is None or self._expiry is None:
            return True
        remaining = (self._expiry - datetime.now(timezone.utc)).total_seconds()
        return remaining < REFRESH_BEFORE_EXPIRY_SECONDS

    def get(self) -> Credentials:
        if self._needs_refresh():
            self._refresh()
        return self._creds

    def _refresh(self) -> None:
        log.info("Fetching fresh credentials from elhaz (config=%s)", self.config_name)
        cmd = ["elhaz"]
        if ELHAZ_SOCKET_PATH:
            cmd += ["--socket-path", ELHAZ_SOCKET_PATH]
        cmd += ["export", "--format", "credential-process", "-n", self.config_name]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
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


class ElhazResignAddon:
    def __init__(self) -> None:
        self.store = CredentialStore()
        self.elhaz = ElhazCredentialCache(ELHAZ_CONFIG)
        start_creds_server(PROXY_SOCK_PATH, self.store)

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        parsed = parse_aws_host(host)
        if parsed is None:
            return

        service, region = parsed
        log.info("Intercepted AWS request: host=%s service=%s region=%s method=%s",
                 host, service, region, flow.request.method)

        # Validate that the request was signed with a proxy-issued keypair
        if not validate_sigv4(flow, self.store):
            log.warning("Rejected request: invalid proxy SigV4 signature")
            flow.response = http.Response.make(
                403,
                json.dumps({
                    "Error": {
                        "Code": "InvalidClientTokenId",
                        "Message": "The security token included in the request is invalid.",
                    }
                }),
                {"Content-Type": "application/json"},
            )
            return

        # Strip proxy auth headers before re-signing
        for h in list(flow.request.headers.keys()):
            if h.lower() in _AUTH_HEADERS:
                del flow.request.headers[h]

        try:
            creds = self.elhaz.get()
        except Exception as exc:
            log.error("Failed to fetch elhaz credentials: %s", exc)
            flow.response = http.Response.make(
                503,
                json.dumps({
                    "Error": {
                        "Code": "ServiceUnavailable",
                        "Message": "Proxy could not obtain IAC credentials.",
                    }
                }),
                {"Content-Type": "application/json"},
            )
            return

        url = flow.request.pretty_url
        body = flow.request.content or b""
        aws_request = AWSRequest(
            method=flow.request.method,
            url=url,
            data=body,
            headers=dict(flow.request.headers),
        )

        SigV4Auth(creds, service, region).add_auth(aws_request)

        for key, value in aws_request.headers.items():
            flow.request.headers[key] = value

        log.info("Request re-signed for %s/%s", service, region)


def load(loader):  # noqa: D103 — mitmproxy hook
    pass


addons = [ElhazResignAddon()]
