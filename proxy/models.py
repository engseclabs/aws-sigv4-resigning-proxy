"""Pydantic models for wire shapes and internal data."""

__all__ = ["CredentialPayload", "ClientCred"]

from datetime import datetime
from pydantic import BaseModel, ConfigDict


class _BaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- #
# Public wire shapes
# --------------------------------------------------------------------------- #

class CredentialPayload(BaseModel):
    """Wire shape returned to the agent via creds.sock / credential_process.

    Must match the AWS credential_process JSON spec exactly — no extra="forbid".
    """
    Version: int = 1
    AccessKeyId: str
    SecretAccessKey: str
    Expiration: str  # ISO 8601


# --------------------------------------------------------------------------- #
# Internal models
# --------------------------------------------------------------------------- #

class ClientCred(_BaseModel):
    """Per-client keypair held in CredentialStore."""
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


# --------------------------------------------------------------------------- #
# Error response shapes (forged AWS error responses)
# --------------------------------------------------------------------------- #

class _ErrorBody(_BaseModel):
    Code: str
    Message: str


class ErrorEnvelope(_BaseModel):
    Error: _ErrorBody

    @classmethod
    def from_exc(cls, code: str, message: str) -> "ErrorEnvelope":
        return cls(Error=_ErrorBody(Code=code, Message=message))
