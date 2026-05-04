"""IAM policy allowlist for enforcement mode.

Loads a standard IAM policy JSON document and checks whether a set of
resolved IAM action strings is permitted.  Only the Allow/NotAction/Resource
dimensions that matter for per-request enforcement are evaluated — condition
keys and principal checks are not in scope.
"""

__all__ = ["Allowlist"]

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)


class Allowlist:
    """Checks resolved IAM actions against a loaded policy document.

    The policy must be standard IAM JSON:
      {"Version": "2012-10-17", "Statement": [...]}

    Only Allow statements with Effect=Allow are used.  Deny statements are
    ignored — the proxy's job is to enforce a positive allowlist, not to
    replicate full IAM evaluation order.

    Action matching supports the '*' wildcard (e.g. "s3:*", "*").
    """

    def __init__(self, policy: dict) -> None:
        # Flatten all Allow statement actions into a single set of lowercase strings.
        # Wildcards are preserved for matching at check time.
        self._allowed: set[str] = set()
        self._wildcard_prefixes: list[str] = []

        for stmt in policy.get("Statement", []):
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                a = action.lower()
                if a == "*":
                    self._wildcard_prefixes.append("")   # matches everything
                elif a.endswith(":*"):
                    self._wildcard_prefixes.append(a[:-1])  # e.g. "s3:"
                else:
                    self._allowed.add(a)

        log.info(
            "Allowlist loaded: %d explicit actions, %d wildcard prefixes",
            len(self._allowed),
            len(self._wildcard_prefixes),
        )

    @classmethod
    def from_file(cls, path: Path) -> "Allowlist":
        with open(path) as f:
            return cls(json.load(f))

    def permits(self, actions: list[str]) -> bool:
        """Return True if every action in the list is covered by the allowlist.

        An empty action list (e.g. permissionless operation) is always permitted.
        """
        for action in actions:
            if not self._permits_one(action):
                return False
        return True

    def _permits_one(self, action: str) -> bool:
        a = action.lower()
        if a in self._allowed:
            return True
        for prefix in self._wildcard_prefixes:
            if a.startswith(prefix):
                return True
        return False
