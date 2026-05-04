"""AWS hostname parsing and local SigV4 signature validation."""

__all__ = ["parse_aws_host", "validate_sigv4"]

import hashlib
import hmac
import logging
import re
from urllib.parse import parse_qs, urlparse

from .credentials import CredentialStore

log = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Hostname → (service, region) parsing
# --------------------------------------------------------------------------- #

_AWS_HOST_PATTERNS = [
    (re.compile(r"^([a-z0-9-]+)\.([a-z]+-[a-z]+-\d+)\.amazonaws\.com$"), lambda m: (m.group(1), m.group(2))),
    (re.compile(r"^s3\.amazonaws\.com$"),           lambda m: ("s3",  "us-east-1")),
    (re.compile(r"^sts\.amazonaws\.com$"),          lambda m: ("sts", "us-east-1")),
    (re.compile(r"^([a-z0-9-]+)\.amazonaws\.com$"), lambda m: (m.group(1), "us-east-1")),
    (re.compile(r"^[^.]+\.s3\.amazonaws\.com$"),    lambda m: ("s3",  "us-east-1")),
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
    parts: dict[str, str] = {}
    for part in auth[len(prefix):].split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            parts[k.strip()] = v.strip()
    return parts if {"Credential", "SignedHeaders", "Signature"} <= parts.keys() else None


def validate_sigv4(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    store: CredentialStore,
) -> bool:
    """
    Recompute the SigV4 signature for the inbound request and compare it
    against the Authorization header. Looks up the signing secret by
    access_key_id so each client is validated against its own keypair.
    """
    auth = headers.get("authorization") or headers.get("Authorization", "")
    parsed = _parse_auth_header(auth)
    if not parsed:
        log.warning("Missing or malformed Authorization header")
        return False

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

    # Build a case-insensitive header lookup
    headers_lower = {k.lower(): v for k, v in headers.items()}
    canonical_headers = "".join(
        f"{h}:{headers_lower.get(h, '').strip()}\n"
        for h in signed_headers
    )
    body_hash = hashlib.sha256(body).hexdigest()
    parsed_url = urlparse(url)
    canonical_uri = parsed_url.path or "/"
    canonical_qs = "&".join(
        sorted(
            f"{k}={v}"
            for k, vs in parse_qs(parsed_url.query, keep_blank_values=True).items()
            for v in vs
        )
    )
    canonical_request = "\n".join([
        method,
        canonical_uri,
        canonical_qs,
        canonical_headers,
        ";".join(signed_headers),
        body_hash,
    ])

    amz_date = headers_lower.get("x-amz-date", "")
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
