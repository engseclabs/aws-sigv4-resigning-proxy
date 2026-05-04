"""Tests for proxy/addon.py — ResignPlugin._handle and handle_client_request."""

import json

import pytest
from botocore.credentials import Credentials

import core.addon as addon_mod
from core.addon import ResignPlugin, _make_reject, _headers_dict
from core.allowlist import Allowlist
from core.credentials import CredentialStore
from core.exceptions import EnforcementError, UpstreamError, ValidationError
from core.resolver import ActionResolver

from conftest import FakeCredentialSource, make_signed_request, make_store_with


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_AUTH_HEADER_NAMES = {"authorization", "x-amz-date", "x-amz-security-token", "x-amz-content-sha256"}


class _FakeResolver:
    """Stub resolver that returns a fixed action list."""
    def __init__(self, actions: list[str]):
        self._actions = actions

    def resolve(self, **kwargs) -> list[str]:
        return self._actions


class _FakeHttpParser:
    """Minimal stub for proxy.http.parser.HttpParser."""

    def __init__(
        self,
        method: str,
        host: str,
        path: str,
        headers: dict[str, str],
        body: bytes = b"",
    ) -> None:
        self.method = method.encode()
        self.host = host.encode()
        self.path = path.encode()
        self.body = body
        # Internal headers format: lowercase key → (original_key_bytes, value_bytes)
        self._h: dict[bytes, tuple[bytes, bytes]] = {
            k.lower().encode(): (k.encode(), v.encode())
            for k, v in headers.items()
        }

    @property
    def headers(self):
        return self._h

    def del_header(self, key: bytes) -> None:
        self._h.pop(key.lower(), None)

    def add_header(self, key: bytes, value: bytes) -> bytes:
        k = key.lower()
        self._h[k] = (key, value)
        return k

    def has_header(self, key: bytes) -> bool:
        return key.lower() in self._h

    def header(self, key: bytes) -> bytes:
        entry = self._h.get(key.lower())
        if entry is None:
            raise KeyError(key)
        return entry[1]


def _make_parser(
    *,
    method: str = "GET",
    host: str = "s3.amazonaws.com",
    path: str = "/bucket/key",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> _FakeHttpParser:
    if headers is None:
        headers = {}
    return _FakeHttpParser(method=method, host=host, path=path, headers=headers, body=body)


def _make_signed_parser(
    *,
    secret: str = "testsecret",
    access_key_id: str = "AKIAPROXYTEST12345678",
    **kwargs,
) -> _FakeHttpParser:
    """Build a _FakeHttpParser with a valid SigV4 Authorization header."""
    method, url, headers, body = make_signed_request(
        secret=secret, access_key_id=access_key_id, **kwargs
    )
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return _FakeHttpParser(
        method=method,
        host=parsed.hostname or "s3.amazonaws.com",
        path=parsed.path or "/",
        headers=headers,
        body=body,
    )


def _make_plugin(
    store: CredentialStore | None = None,
    cred_source=None,
    allowlist=None,
    resolver=None,
) -> ResignPlugin:
    """Build a ResignPlugin without starting the real creds server or singleton init."""
    plugin = object.__new__(ResignPlugin)
    # Patch module-level singletons for this test
    addon_mod._store = store or make_store_with()
    addon_mod._upstream_creds = cred_source or FakeCredentialSource()
    addon_mod._allowlist = allowlist
    addon_mod._resolver = resolver or _FakeResolver([])
    return plugin


# --------------------------------------------------------------------------- #
# _make_reject
# --------------------------------------------------------------------------- #

def test_make_reject_status_for_validation_error():
    exc = ValidationError("bad token")
    rej = _make_reject(exc)
    assert rej.status_code == 403


def test_make_reject_status_for_upstream_error():
    exc = UpstreamError("down")
    rej = _make_reject(exc)
    assert rej.status_code == 503


def test_make_reject_body_is_error_envelope():
    exc = ValidationError("bad token")
    rej = _make_reject(exc)
    body = json.loads(rej.body)
    assert body["Error"]["Code"] == "InvalidClientTokenId"
    assert "bad token" in body["Error"]["Message"]


def test_make_reject_content_type():
    rej = _make_reject(ValidationError("x"))
    assert rej.headers.get(b"Content-Type") == b"application/json"


# --------------------------------------------------------------------------- #
# _handle — validation
# --------------------------------------------------------------------------- #

def test_handle_raises_validation_error_on_bad_sig():
    plugin = _make_plugin(store=make_store_with(secret="correct"))
    request = _make_signed_parser(secret="wrong")
    with pytest.raises(ValidationError):
        plugin._handle(request, "s3", "us-east-1")


def test_handle_raises_upstream_error_when_creds_fail():
    plugin = _make_plugin(cred_source=FakeCredentialSource(raises=RuntimeError("no creds")))
    request = _make_signed_parser()
    with pytest.raises(UpstreamError):
        plugin._handle(request, "s3", "us-east-1")


# --------------------------------------------------------------------------- #
# _handle — header stripping and re-signing
# --------------------------------------------------------------------------- #

def test_handle_strips_inbound_auth_headers():
    plugin = _make_plugin()
    request = _make_signed_parser()
    old_auth = request.header(b"authorization").decode()
    request.add_header(b"x-amz-security-token", b"oldtoken")
    plugin._handle(request, "s3", "us-east-1")
    assert not request.has_header(b"x-amz-security-token")
    new_auth = request.header(b"authorization").decode()
    assert new_auth != old_auth


def test_handle_adds_new_authorization_header():
    plugin = _make_plugin()
    request = _make_signed_parser()
    plugin._handle(request, "s3", "us-east-1")
    assert request.has_header(b"authorization")


def test_handle_new_auth_is_aws_sigv4():
    plugin = _make_plugin()
    request = _make_signed_parser()
    plugin._handle(request, "s3", "us-east-1")
    auth = request.header(b"authorization").decode()
    assert auth.startswith("AWS4-HMAC-SHA256 ")


# --------------------------------------------------------------------------- #
# handle_client_request — non-AWS passthrough
# --------------------------------------------------------------------------- #

def test_handle_client_request_skips_non_aws_hosts():
    plugin = _make_plugin()
    request = _make_parser(host="example.com")
    result = plugin.handle_client_request(request)
    assert result is request  # returned unchanged


# --------------------------------------------------------------------------- #
# handle_client_request — AWS host triggers _handle
# --------------------------------------------------------------------------- #

def test_handle_client_request_raises_on_validation_failure():
    from proxy.http.exception import HttpRequestRejected
    plugin = _make_plugin(store=make_store_with(secret="correct"))
    request = _make_signed_parser(secret="wrong")
    with pytest.raises(HttpRequestRejected) as exc_info:
        plugin.handle_client_request(request)
    assert exc_info.value.status_code == 403


def test_handle_client_request_raises_on_upstream_failure():
    from proxy.http.exception import HttpRequestRejected
    plugin = _make_plugin(cred_source=FakeCredentialSource(raises=RuntimeError("no creds")))
    request = _make_signed_parser()
    with pytest.raises(HttpRequestRejected) as exc_info:
        plugin.handle_client_request(request)
    assert exc_info.value.status_code == 503


def test_handle_client_request_successful_resign_returns_request():
    plugin = _make_plugin()
    request = _make_signed_parser()
    result = plugin.handle_client_request(request)
    assert result is request


# --------------------------------------------------------------------------- #
# Enforcement mode
# --------------------------------------------------------------------------- #

def _make_enforce_plugin(allowed_actions: list[str], resolved_actions: list[str]):
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": allowed_actions, "Resource": "*"}],
    }
    return _make_plugin(
        allowlist=Allowlist(policy),
        resolver=_FakeResolver(resolved_actions),
    )


def test_enforcement_permits_allowed_action():
    plugin = _make_enforce_plugin(["s3:GetObject"], ["s3:GetObject"])
    request = _make_signed_parser()
    result = plugin._handle(request, "s3", "us-east-1")
    assert result is request


def test_enforcement_blocks_denied_action():
    plugin = _make_enforce_plugin(["s3:GetObject"], ["s3:DeleteObject"])
    request = _make_signed_parser()
    with pytest.raises(EnforcementError):
        plugin._handle(request, "s3", "us-east-1")


def test_enforcement_blocked_raises_http_rejected_with_403():
    from proxy.http.exception import HttpRequestRejected
    plugin = _make_enforce_plugin(["s3:GetObject"], ["s3:DeleteObject"])
    request = _make_signed_parser()
    with pytest.raises(HttpRequestRejected) as exc_info:
        plugin.handle_client_request(request)
    assert exc_info.value.status_code == 403


def test_enforcement_blocked_body_has_access_denied_code():
    from proxy.http.exception import HttpRequestRejected
    plugin = _make_enforce_plugin(["s3:GetObject"], ["s3:DeleteObject"])
    request = _make_signed_parser()
    with pytest.raises(HttpRequestRejected) as exc_info:
        plugin.handle_client_request(request)
    body = json.loads(exc_info.value.body)
    assert body["Error"]["Code"] == "AccessDenied"


def test_enforcement_permits_empty_action_list():
    plugin = _make_enforce_plugin([], [])
    request = _make_signed_parser()
    result = plugin._handle(request, "s3", "us-east-1")
    assert result is request


def test_enforcement_permits_wildcard_service():
    plugin = _make_enforce_plugin(["s3:*"], ["s3:PutObject"])
    request = _make_signed_parser()
    result = plugin._handle(request, "s3", "us-east-1")
    assert result is request


def test_enforcement_blocks_multi_action_if_any_denied():
    plugin = _make_enforce_plugin(["s3:GetObject"], ["s3:GetObject", "s3:PutObject"])
    request = _make_signed_parser()
    with pytest.raises(EnforcementError):
        plugin._handle(request, "s3", "us-east-1")


def test_make_reject_status_for_enforcement_error():
    exc = EnforcementError("not allowed")
    rej = _make_reject(exc)
    assert rej.status_code == 403


def test_make_reject_code_for_enforcement_error():
    exc = EnforcementError("not allowed")
    rej = _make_reject(exc)
    body = json.loads(rej.body)
    assert body["Error"]["Code"] == "AccessDenied"
