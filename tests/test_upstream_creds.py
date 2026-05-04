"""Tests for proxy/upstream_creds.py — BotoCredentialSource."""

from unittest.mock import MagicMock, patch

from botocore.credentials import Credentials

from core.upstream_creds import BotoCredentialSource


def _mock_session(access_key: str = "AKIAFAKE", secret: str = "fakesecret", token: str | None = None):
    frozen = MagicMock()
    frozen.access_key = access_key
    frozen.secret_key = secret
    frozen.token = token

    resolver = MagicMock()
    resolver.get_frozen_credentials.return_value = frozen

    session = MagicMock()
    session.get_credentials.return_value = resolver
    return session


def test_get_returns_credentials_object():
    src = BotoCredentialSource()
    with patch("core.upstream_creds.boto3.Session", return_value=_mock_session()):
        result = src.get()
    assert isinstance(result, Credentials)


def test_get_maps_access_key():
    src = BotoCredentialSource()
    with patch("core.upstream_creds.boto3.Session", return_value=_mock_session(access_key="AKIATEST")):
        result = src.get()
    assert result.access_key == "AKIATEST"


def test_get_maps_secret_key():
    src = BotoCredentialSource()
    with patch("core.upstream_creds.boto3.Session", return_value=_mock_session(secret="mysecret")):
        result = src.get()
    assert result.secret_key == "mysecret"


def test_get_maps_session_token():
    src = BotoCredentialSource()
    with patch("core.upstream_creds.boto3.Session", return_value=_mock_session(token="mytoken")):
        result = src.get()
    assert result.token == "mytoken"


def test_get_maps_none_token():
    src = BotoCredentialSource()
    with patch("core.upstream_creds.boto3.Session", return_value=_mock_session(token=None)):
        result = src.get()
    assert result.token is None


def test_get_calls_get_frozen_credentials():
    src = BotoCredentialSource()
    session = _mock_session()
    with patch("core.upstream_creds.boto3.Session", return_value=session):
        src.get()
    session.get_credentials.return_value.get_frozen_credentials.assert_called_once()
