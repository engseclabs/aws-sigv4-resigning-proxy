"""Shared fixtures, stubs, and helpers for the test suite."""

import hashlib
import hmac
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from botocore.credentials import Credentials

from core.credentials import CredentialStore, _serve_creds
from core.models import ClientCred, CredentialPayload


# --------------------------------------------------------------------------- #
# Helpers (plain functions, not fixtures)
# --------------------------------------------------------------------------- #

def make_client_cred(
    *,
    access_key_id: str = "AKIAPROXYTEST12345678",
    secret_access_key: str = "testsecret",
    prev_secret: str | None = None,
    expiry: datetime | None = None,
) -> ClientCred:
    if expiry is None:
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    return ClientCred(
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        prev_secret=prev_secret,
        expiry=expiry,
    )


def make_store_with(
    access_key_id: str = "AKIAPROXYTEST12345678",
    secret: str = "testsecret",
    prev_secret: str | None = None,
) -> CredentialStore:
    store = CredentialStore()
    cred = make_client_cred(
        access_key_id=access_key_id,
        secret_access_key=secret,
        prev_secret=prev_secret,
    )
    store._store[access_key_id] = cred
    return store


def _hmac_sha256(key: bytes, data: str) -> bytes:
    return hmac.new(key, data.encode(), hashlib.sha256).digest()


def _signing_key(secret: str, date_str: str, region: str, service: str) -> bytes:
    k = _hmac_sha256(("AWS4" + secret).encode(), date_str)
    k = _hmac_sha256(k, region)
    k = _hmac_sha256(k, service)
    return _hmac_sha256(k, "aws4_request")


def make_signed_request(
    *,
    method: str = "GET",
    host: str = "s3.amazonaws.com",
    scheme: str = "https",
    path: str = "/bucket/key",
    body: bytes = b"",
    access_key_id: str = "AKIAPROXYTEST12345678",
    secret: str = "testsecret",
    service: str = "s3",
    region: str = "us-east-1",
    date_str: str = "20240101",
    amz_date: str = "20240101T000000Z",
    extra_headers: dict[str, str] | None = None,
) -> tuple[str, str, dict[str, str], bytes]:
    """Return (method, url, headers, body) with a valid SigV4 Authorization header."""
    from urllib.parse import urlparse

    headers: dict[str, str] = {"host": host, "x-amz-date": amz_date}
    if extra_headers:
        headers.update(extra_headers)

    signed_headers = sorted(headers.keys())
    canonical_headers = "".join(f"{h}:{headers[h].strip()}\n" for h in signed_headers)
    body_hash = hashlib.sha256(body).hexdigest()

    url = f"{scheme}://{host}{path}"
    parsed_url = urlparse(url)
    canonical_uri = parsed_url.path or "/"
    canonical_qs = ""

    canonical_request = "\n".join([
        method,
        canonical_uri,
        canonical_qs,
        canonical_headers,
        ";".join(signed_headers),
        body_hash,
    ])
    scope = f"{date_str}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])
    key = _signing_key(secret, date_str, region, service)
    sig = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = (
        f"AWS4-HMAC-SHA256 "
        f"Credential={access_key_id}/{scope},"
        f"SignedHeaders={';'.join(signed_headers)},"
        f"Signature={sig}"
    )
    headers["authorization"] = auth
    return method, url, headers, body


# --------------------------------------------------------------------------- #
# FakeCredentialSource stub
# --------------------------------------------------------------------------- #

class FakeCredentialSource:
    """Stub for BotoCredentialSource in addon tests."""

    def __init__(self, creds: Credentials | None = None, *, raises: Exception | None = None):
        self._creds = creds or Credentials("FAKEAKID", "fakesecret", None)
        self._raises = raises

    def get(self) -> Credentials:
        if self._raises:
            raise self._raises
        return self._creds


# --------------------------------------------------------------------------- #
# Socket server fixture for credential integration tests
# --------------------------------------------------------------------------- #

def _wait_for_socket(path: Path, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise TimeoutError(f"Socket never appeared at {path}")


def _short_sock_path() -> Path:
    """Return a short socket path under /tmp to stay within the 104-byte AF_UNIX limit."""
    import uuid
    return Path(f"/tmp/ep_{uuid.uuid4().hex[:8]}.sock")


@pytest.fixture()
def cred_sock_path() -> Path:
    return _short_sock_path()


@pytest.fixture()
def running_creds_server(cred_sock_path):
    store = CredentialStore()
    t = threading.Thread(target=_serve_creds, args=(cred_sock_path, store), daemon=True)
    t.start()
    _wait_for_socket(cred_sock_path)
    yield cred_sock_path, store
    # daemon thread exits with the test process; socket cleaned up by OS
