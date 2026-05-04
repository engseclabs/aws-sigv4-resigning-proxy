"""Tests for core/upstream_creds.py — BotoCredentialSource."""

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


def _make_src(session=None):
    """Build a BotoCredentialSource with a mocked boto3.Session."""
    mock = session or _mock_session()
    with patch("core.upstream_creds.boto3.Session", return_value=mock):
        src = BotoCredentialSource()
    src._session = mock  # keep mock accessible after patch exits
    return src, mock


def test_get_returns_credentials_object():
    src, _ = _make_src()
    assert isinstance(src.get(), Credentials)


def test_get_maps_access_key():
    src, _ = _make_src(_mock_session(access_key="AKIATEST"))
    assert src.get().access_key == "AKIATEST"


def test_get_maps_secret_key():
    src, _ = _make_src(_mock_session(secret="mysecret"))
    assert src.get().secret_key == "mysecret"


def test_get_maps_session_token():
    src, _ = _make_src(_mock_session(token="mytoken"))
    assert src.get().token == "mytoken"


def test_get_maps_none_token():
    src, _ = _make_src(_mock_session(token=None))
    assert src.get().token is None


def test_session_reused_across_calls():
    """get() must reuse the same session so RefreshableCredentials can refresh."""
    src, mock = _make_src()
    src.get()
    src.get()
    src.get()
    assert mock.get_credentials.call_count == 3  # called each time, but same session object


def test_uses_default_credential_chain():
    """BotoCredentialSource must not hard-code any profile name."""
    with patch("core.upstream_creds.boto3.Session", return_value=_mock_session()) as mock_cls:
        BotoCredentialSource()
    mock_cls.assert_called_once_with()


def test_get_calls_get_frozen_credentials():
    src, mock = _make_src()
    src.get()
    mock.get_credentials.return_value.get_frozen_credentials.assert_called_once()
