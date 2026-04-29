"""Tests for proxy/elhaz.py — ElhazCredentialCache unit tests."""

import json
import subprocess
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from proxy.elhaz import REFRESH_BEFORE_EXPIRY_SECONDS, ElhazCredentialCache


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _future_expiry(seconds: int = 3600) -> str:
    dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _expired_expiry(seconds: int = 10) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_cred_output(
    access_key_id: str = "AKIAFAKE",
    secret: str = "fakesecret",
    expiry: str | None = None,
    session_token: str | None = None,
) -> str:
    data: dict = {
        "Version": 1,
        "AccessKeyId": access_key_id,
        "SecretAccessKey": secret,
    }
    if expiry:
        data["Expiration"] = expiry
    if session_token:
        data["SessionToken"] = session_token
    return json.dumps(data)


# --------------------------------------------------------------------------- #
# _needs_refresh
# --------------------------------------------------------------------------- #

def test_needs_refresh_when_no_creds():
    cache = ElhazCredentialCache("test-config")
    assert cache._needs_refresh() is True


def test_needs_refresh_when_expiry_is_none():
    cache = ElhazCredentialCache("test-config")
    cache._creds = MagicMock()
    cache._expiry = None
    assert cache._needs_refresh() is True


def test_needs_refresh_when_far_future_expiry():
    cache = ElhazCredentialCache("test-config")
    cache._creds = MagicMock()
    cache._expiry = datetime.now(timezone.utc) + timedelta(hours=2)
    assert cache._needs_refresh() is False


def test_needs_refresh_when_expiry_within_threshold():
    cache = ElhazCredentialCache("test-config")
    cache._creds = MagicMock()
    # Just inside the refresh window
    cache._expiry = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_BEFORE_EXPIRY_SECONDS - 10)
    assert cache._needs_refresh() is True


# --------------------------------------------------------------------------- #
# _refresh
# --------------------------------------------------------------------------- #

def test_refresh_parses_credentials(monkeypatch):
    expiry = _future_expiry()
    result = MagicMock()
    result.stdout = _make_cred_output(
        access_key_id="AKIAFAKE123",
        secret="secret456",
        expiry=expiry,
    )
    monkeypatch.setattr("proxy.elhaz.subprocess.run", lambda *a, **kw: result)

    cache = ElhazCredentialCache("test-config")
    cache._refresh()

    assert cache._creds.access_key == "AKIAFAKE123"
    assert cache._creds.secret_key == "secret456"
    assert cache._expiry is not None


def test_refresh_handles_missing_expiration(monkeypatch):
    result = MagicMock()
    result.stdout = _make_cred_output()  # no Expiration key
    monkeypatch.setattr("proxy.elhaz.subprocess.run", lambda *a, **kw: result)

    cache = ElhazCredentialCache("test-config")
    cache._refresh()
    assert cache._expiry is None


def test_refresh_propagates_subprocess_error(monkeypatch):
    def _raise(*a, **kw):
        raise subprocess.CalledProcessError(1, "elhaz")
    monkeypatch.setattr("proxy.elhaz.subprocess.run", _raise)

    cache = ElhazCredentialCache("test-config")
    with pytest.raises(subprocess.CalledProcessError):
        cache._refresh()


# --------------------------------------------------------------------------- #
# get
# --------------------------------------------------------------------------- #

def test_get_calls_refresh_when_stale(monkeypatch):
    result = MagicMock()
    result.stdout = _make_cred_output(expiry=_future_expiry())
    calls = []

    def fake_run(*a, **kw):
        calls.append(a)
        return result

    monkeypatch.setattr("proxy.elhaz.subprocess.run", fake_run)

    cache = ElhazCredentialCache("test-config")
    cache.get()
    assert len(calls) == 1


def test_get_does_not_refresh_when_fresh(monkeypatch):
    result = MagicMock()
    result.stdout = _make_cred_output(expiry=_future_expiry())
    calls = []

    def fake_run(*a, **kw):
        calls.append(a)
        return result

    monkeypatch.setattr("proxy.elhaz.subprocess.run", fake_run)

    cache = ElhazCredentialCache("test-config")
    cache.get()   # first call — fetches
    cache.get()   # second call — should use cached
    assert len(calls) == 1


def test_get_re_fetches_when_near_expiry(monkeypatch):
    result = MagicMock()
    result.stdout = _make_cred_output(expiry=_future_expiry())
    calls = []

    def fake_run(*a, **kw):
        calls.append(a)
        return result

    monkeypatch.setattr("proxy.elhaz.subprocess.run", fake_run)

    cache = ElhazCredentialCache("test-config")
    cache.get()  # initial fetch
    # Force expiry into the refresh window
    cache._expiry = datetime.now(timezone.utc) + timedelta(seconds=REFRESH_BEFORE_EXPIRY_SECONDS - 5)
    cache.get()  # should trigger refresh
    assert len(calls) == 2


def test_get_includes_socket_path_when_env_set(monkeypatch):
    monkeypatch.setenv("ELHAZ_SOCKET_PATH", "/tmp/test.sock")
    # Re-import to pick up env var
    import importlib
    import proxy.elhaz as elhaz_mod
    importlib.reload(elhaz_mod)

    result = MagicMock()
    result.stdout = _make_cred_output(expiry=_future_expiry())
    captured = []

    def fake_run(cmd, **kw):
        captured.append(cmd)
        return result

    monkeypatch.setattr(elhaz_mod, "subprocess", MagicMock(run=fake_run))

    cache = elhaz_mod.ElhazCredentialCache("test-config")
    cache._refresh()

    assert "--socket-path" in captured[0]
    assert "/tmp/test.sock" in captured[0]
