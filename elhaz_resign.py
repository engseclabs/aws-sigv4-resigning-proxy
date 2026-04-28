"""
mitmproxy addon: intercept AWS API requests and re-sign them using
credentials vended by elhaz, so the caller needs no ambient AWS credentials.

Usage:
    mitmdump --listen-port 8080 --scripts elhaz_resign.py

Config:
    Set ELHAZ_CONFIG_NAME env var or edit ELHAZ_CONFIG below.
"""

import json
import logging
import os
import subprocess
import re
from datetime import datetime, timezone

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from mitmproxy import http

log = logging.getLogger(__name__)

ELHAZ_CONFIG = os.environ.get("ELHAZ_CONFIG_NAME", "sandbox-elhaz")
REFRESH_BEFORE_EXPIRY_SECONDS = 300  # refresh when < 5 min remain

# --------------------------------------------------------------------------- #
# Hostname → (service, region) parsing
# --------------------------------------------------------------------------- #

# Patterns ordered from most-specific to least-specific
_AWS_HOST_PATTERNS = [
    # s3.us-east-1.amazonaws.com  →  s3, us-east-1
    (re.compile(r"^([a-z0-9-]+)\.([a-z]+-[a-z]+-\d+)\.amazonaws\.com$"), lambda m: (m.group(1), m.group(2))),
    # s3.amazonaws.com  →  s3, us-east-1  (global S3 endpoint)
    (re.compile(r"^s3\.amazonaws\.com$"), lambda m: ("s3", "us-east-1")),
    # sts.amazonaws.com  →  sts, us-east-1  (global STS endpoint)
    (re.compile(r"^sts\.amazonaws\.com$"), lambda m: ("sts", "us-east-1")),
    # <service>.amazonaws.com  generic global fallback
    (re.compile(r"^([a-z0-9-]+)\.amazonaws\.com$"), lambda m: (m.group(1), "us-east-1")),
    # bucket.s3.amazonaws.com  (path-style virtual-hosted S3)
    (re.compile(r"^[^.]+\.s3\.amazonaws\.com$"), lambda m: ("s3", "us-east-1")),
    # bucket.s3.us-west-2.amazonaws.com
    (re.compile(r"^[^.]+\.s3\.([a-z]+-[a-z]+-\d+)\.amazonaws\.com$"), lambda m: ("s3", m.group(1))),
]


def parse_aws_host(host: str) -> tuple[str, str] | None:
    """Return (service, region) from an AWS hostname, or None if not AWS."""
    host = host.lower().split(":")[0]  # strip port if present
    if "amazonaws.com" not in host:
        return None
    for pattern, extractor in _AWS_HOST_PATTERNS:
        m = pattern.match(host)
        if m:
            return extractor(m)
    log.warning("Could not parse AWS host: %s", host)
    return None


# --------------------------------------------------------------------------- #
# Credential cache
# --------------------------------------------------------------------------- #

class ElhazCredentialCache:
    def __init__(self, config_name: str) -> None:
        self.config_name = config_name
        self._creds: Credentials | None = None
        self._expiry: datetime | None = None

    def _needs_refresh(self) -> bool:
        if self._creds is None or self._expiry is None:
            return True
        now = datetime.now(timezone.utc)
        remaining = (self._expiry - now).total_seconds()
        return remaining < REFRESH_BEFORE_EXPIRY_SECONDS

    def get(self) -> Credentials:
        if self._needs_refresh():
            self._refresh()
        return self._creds

    def _refresh(self) -> None:
        log.info("Fetching fresh credentials from elhaz (config=%s)", self.config_name)
        result = subprocess.run(
            ["elhaz", "export", "--format", "credential-process", "-n", self.config_name],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        self._creds = Credentials(
            access_key=data["AccessKeyId"],
            secret_key=data["SecretAccessKey"],
            token=data.get("SessionToken"),
        )
        expiry_str = data.get("Expiration")
        if expiry_str:
            # ISO 8601 with offset — fromisoformat handles +00:00 on 3.11+,
            # but replace Z just in case an older format appears.
            self._expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
        else:
            self._expiry = None
        log.info("Credentials refreshed; expiry=%s", self._expiry)


# --------------------------------------------------------------------------- #
# mitmproxy addon
# --------------------------------------------------------------------------- #

_AUTH_HEADERS = {
    "authorization",
    "x-amz-date",
    "x-amz-security-token",
    "x-amz-content-sha256",
}


class ElhazResignAddon:
    def __init__(self) -> None:
        self.cache = ElhazCredentialCache(ELHAZ_CONFIG)

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        parsed = parse_aws_host(host)
        if parsed is None:
            return

        service, region = parsed
        log.info("Intercepted AWS request: host=%s service=%s region=%s method=%s",
                 host, service, region, flow.request.method)

        # Strip existing AWS auth headers
        for h in list(flow.request.headers.keys()):
            if h.lower() in _AUTH_HEADERS:
                del flow.request.headers[h]

        # Fetch credentials from elhaz
        try:
            creds = self.cache.get()
        except Exception as exc:
            log.error("Failed to fetch elhaz credentials: %s", exc)
            return

        # Reconstruct the full URL for botocore
        url = flow.request.pretty_url

        # Build an AWSRequest so botocore can sign it
        body = flow.request.content or b""
        headers = dict(flow.request.headers)

        aws_request = AWSRequest(
            method=flow.request.method,
            url=url,
            data=body,
            headers=headers,
        )

        # Sign
        signer = SigV4Auth(creds, service, region)
        signer.add_auth(aws_request)

        # Apply signed headers back onto the intercepted request
        for key, value in aws_request.headers.items():
            flow.request.headers[key] = value

        log.info("Request re-signed for %s/%s", service, region)


def load(loader):  # noqa: D103 — mitmproxy hook
    pass


# Register the addon
addons = [ElhazResignAddon()]
