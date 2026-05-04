"""Tests for proxy/credentials.py — CredentialStore unit tests + socket integration."""

import json
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.credentials import (
    CredentialStore,
    _new_access_key_id,
    _prepare_socket_path,
)
from core.exceptions import ProxyError
from core.models import ClientCred

from conftest import make_client_cred, _short_sock_path


# --------------------------------------------------------------------------- #
# _new_access_key_id
# --------------------------------------------------------------------------- #

def test_access_key_id_prefix():
    kid = _new_access_key_id()
    assert kid.startswith("AKIAPROXY")


def test_access_key_id_length():
    assert len(_new_access_key_id()) == 20


def test_access_key_id_unique():
    ids = {_new_access_key_id() for _ in range(50)}
    assert len(ids) == 50


# --------------------------------------------------------------------------- #
# CredentialStore.issue
# --------------------------------------------------------------------------- #

def test_issue_returns_client_cred():
    store = CredentialStore()
    cred = store.issue()
    assert isinstance(cred, ClientCred)


def test_issue_stores_credential():
    store = CredentialStore()
    cred = store.issue()
    assert cred.access_key_id in store._store


def test_issue_credentials_are_unique():
    store = CredentialStore()
    ids = {store.issue().access_key_id for _ in range(20)}
    assert len(ids) == 20


def test_issue_expiry_in_future():
    store = CredentialStore()
    cred = store.issue()
    assert cred.expiry > datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# CredentialStore.valid_secrets_for
# --------------------------------------------------------------------------- #

def test_valid_secrets_unknown_key_returns_none():
    store = CredentialStore()
    assert store.valid_secrets_for("AKIAUNKNOWN12345678") is None


def test_valid_secrets_known_key_returns_current():
    store = CredentialStore()
    cred = store.issue()
    secrets = store.valid_secrets_for(cred.access_key_id)
    assert secrets == [cred.secret_access_key]


def test_valid_secrets_includes_prev_secret_when_set():
    store = CredentialStore()
    expiry = datetime.now(timezone.utc) + timedelta(hours=1)
    cred = ClientCred(
        access_key_id="AKIAPROXYTEST12345678",
        secret_access_key="current",
        prev_secret="previous",
        expiry=expiry,
    )
    store._store[cred.access_key_id] = cred
    secrets = store.valid_secrets_for(cred.access_key_id)
    assert secrets == ["current", "previous"]


def test_valid_secrets_no_prev_secret_list_length_one():
    store = CredentialStore()
    cred = store.issue()
    secrets = store.valid_secrets_for(cred.access_key_id)
    assert len(secrets) == 1


# --------------------------------------------------------------------------- #
# _prepare_socket_path
# --------------------------------------------------------------------------- #

def test_prepare_creates_parent_dirs(tmp_path):
    sock_path = tmp_path / "sub" / "dir" / "creds.sock"
    _prepare_socket_path(sock_path)
    assert sock_path.parent.exists()


def test_prepare_removes_stale_socket():
    sock_path = _short_sock_path()
    # Create a real socket file (not plain file) so connect raises ECONNREFUSED
    dead = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    dead.bind(str(sock_path))
    dead.close()
    # Socket is bound but not listening — connect will get ECONNREFUSED
    _prepare_socket_path(sock_path)
    assert not sock_path.exists()


def test_prepare_raises_if_live_server_present():
    sock_path = _short_sock_path()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(sock_path))
    srv.listen(1)
    try:
        with pytest.raises(ProxyError, match="already listening"):
            _prepare_socket_path(sock_path)
    finally:
        srv.close()
        sock_path.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Integration: Unix socket credential server
# --------------------------------------------------------------------------- #

def test_creds_server_returns_valid_json(running_creds_server):
    sock_path, _store = running_creds_server
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(3.0)
        s.connect(str(sock_path))
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    payload = json.loads(data)
    assert payload["Version"] == 1
    assert payload["AccessKeyId"].startswith("AKIAPROXY")
    assert "SecretAccessKey" in payload
    assert "Expiration" in payload


def test_creds_server_issues_unique_keypairs_per_connection(running_creds_server):
    sock_path, _store = running_creds_server

    def fetch():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(3.0)
            s.connect(str(sock_path))
            data = b""
            while chunk := s.recv(4096):
                data += chunk
        return json.loads(data)["AccessKeyId"]

    ids = {fetch() for _ in range(5)}
    assert len(ids) == 5


def test_creds_server_registers_issued_key_in_store(running_creds_server):
    sock_path, store = running_creds_server
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(3.0)
        s.connect(str(sock_path))
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    payload = json.loads(data)
    assert store.valid_secrets_for(payload["AccessKeyId"]) is not None
