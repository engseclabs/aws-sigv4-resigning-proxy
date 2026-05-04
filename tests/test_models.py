"""Tests for proxy/models.py — schema contract."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from core.models import ClientCred, CredentialPayload, ErrorEnvelope


# --------------------------------------------------------------------------- #
# CredentialPayload
# --------------------------------------------------------------------------- #

def test_credential_payload_happy_path():
    p = CredentialPayload(
        AccessKeyId="AKIATEST",
        SecretAccessKey="secret",
        Expiration="2024-01-01T00:00:00Z",
    )
    assert p.Version == 1
    assert p.AccessKeyId == "AKIATEST"


def test_credential_payload_allows_extra_fields():
    # Must NOT raise — no extra="forbid" on this model (AWS spec compliance)
    p = CredentialPayload(
        AccessKeyId="AKIATEST",
        SecretAccessKey="secret",
        Expiration="2024-01-01T00:00:00Z",
        SessionToken="tok",  # extra field
    )
    assert p.AccessKeyId == "AKIATEST"


def test_credential_payload_requires_access_key_id():
    with pytest.raises(ValidationError):
        CredentialPayload(SecretAccessKey="s", Expiration="2024-01-01T00:00:00Z")


def test_credential_payload_requires_secret():
    with pytest.raises(ValidationError):
        CredentialPayload(AccessKeyId="A", Expiration="2024-01-01T00:00:00Z")


def test_credential_payload_requires_expiration():
    with pytest.raises(ValidationError):
        CredentialPayload(AccessKeyId="A", SecretAccessKey="s")


# --------------------------------------------------------------------------- #
# ClientCred
# --------------------------------------------------------------------------- #

def test_client_cred_happy_path():
    expiry = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    c = ClientCred(
        access_key_id="AKIAPROXYTEST12345678",
        secret_access_key="secret",
        expiry=expiry,
    )
    assert c.prev_secret is None


def test_client_cred_with_prev_secret():
    expiry = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    c = ClientCred(
        access_key_id="AKIAPROXYTEST12345678",
        secret_access_key="new",
        prev_secret="old",
        expiry=expiry,
    )
    assert c.prev_secret == "old"


def test_client_cred_rejects_extra_fields():
    expiry = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(ValidationError):
        ClientCred(
            access_key_id="AKIAPROXYTEST12345678",
            secret_access_key="s",
            expiry=expiry,
            unexpected="x",
        )


def test_client_cred_to_payload_format():
    expiry = datetime(2024, 6, 1, 12, 30, 45, tzinfo=timezone.utc)
    c = ClientCred(
        access_key_id="AKIAPROXYTEST12345678",
        secret_access_key="mysecret",
        expiry=expiry,
    )
    p = c.to_payload()
    assert isinstance(p, CredentialPayload)
    assert p.AccessKeyId == "AKIAPROXYTEST12345678"
    assert p.SecretAccessKey == "mysecret"
    assert p.Expiration == "2024-06-01T12:30:45Z"


# --------------------------------------------------------------------------- #
# ErrorEnvelope
# --------------------------------------------------------------------------- #

def test_error_envelope_from_exc():
    env = ErrorEnvelope.from_exc("InvalidClientTokenId", "bad token")
    assert env.Error.Code == "InvalidClientTokenId"
    assert env.Error.Message == "bad token"


def test_error_envelope_rejects_extra_fields():
    with pytest.raises(ValidationError):
        ErrorEnvelope(Error={"Code": "X", "Message": "y", "Extra": "z"})


def test_error_envelope_json_roundtrip():
    env = ErrorEnvelope.from_exc("ServiceUnavailable", "down")
    data = env.model_dump_json()
    restored = ErrorEnvelope.model_validate_json(data)
    assert restored.Error.Code == "ServiceUnavailable"
