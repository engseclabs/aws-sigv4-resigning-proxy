"""iam-agent-proxy — public API."""

from .credentials import CredentialStore, start_creds_server
from .exceptions import ProxyError, UpstreamError, ValidationError, error_status
from .models import ClientCred, CredentialPayload, ErrorEnvelope
from .sigv4 import parse_aws_host, validate_sigv4
from .upstream_creds import BotoCredentialSource

__all__ = [
    # credentials
    "CredentialStore",
    "start_creds_server",
    # upstream creds
    "BotoCredentialSource",
    # exceptions
    "ProxyError",
    "UpstreamError",
    "ValidationError",
    "error_status",
    # models
    "ClientCred",
    "CredentialPayload",
    "ErrorEnvelope",
    # sigv4
    "parse_aws_host",
    "validate_sigv4",
]
