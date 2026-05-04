"""elhaz IAC credential cache — fetches and refreshes credentials via the elhaz CLI.

NOTE: This module is used only by the Docker-compose path (docker/proxy/).
      The native (non-Docker) path uses proxy.upstream_creds.BotoCredentialSource instead.
      Do not import this module from addon.py or iam_agent_proxy.py.
"""

__all__ = ["ElhazCredentialCache"]

import json
import logging
import os
import subprocess
from datetime import datetime, timezone

from botocore.credentials import Credentials

log = logging.getLogger(__name__)

ELHAZ_CONFIG = os.environ.get("ELHAZ_CONFIG_NAME", "sandbox-elhaz")
ELHAZ_SOCKET_PATH = os.environ.get("ELHAZ_SOCKET_PATH")  # None → elhaz uses its default
REFRESH_BEFORE_EXPIRY_SECONDS = 300


class ElhazCredentialCache:
    """Fetches IAC credentials from the elhaz daemon and caches them until near expiry."""

    def __init__(self, config_name: str) -> None:
        self._config_name = config_name
        self._creds: Credentials | None = None
        self._expiry: datetime | None = None

    def _needs_refresh(self) -> bool:
        if self._creds is None or self._expiry is None:
            return True
        return (self._expiry - datetime.now(timezone.utc)).total_seconds() < REFRESH_BEFORE_EXPIRY_SECONDS

    def get(self) -> Credentials:
        if self._needs_refresh():
            self._refresh()
        return self._creds  # type: ignore[return-value]

    def _refresh(self) -> None:
        log.info("Fetching fresh credentials from elhaz (config=%s)", self._config_name)
        cmd = ["elhaz"]
        if ELHAZ_SOCKET_PATH:
            cmd += ["--socket-path", ELHAZ_SOCKET_PATH]
        cmd += ["export", "--format", "credential-process", "-n", self._config_name]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        self._creds = Credentials(
            access_key=data["AccessKeyId"],
            secret_key=data["SecretAccessKey"],
            token=data.get("SessionToken"),
        )
        expiry_str = data.get("Expiration")
        self._expiry = (
            datetime.fromisoformat(expiry_str.replace("Z", "+00:00")) if expiry_str else None
        )
        log.info("Credentials refreshed; expiry=%s", self._expiry)
