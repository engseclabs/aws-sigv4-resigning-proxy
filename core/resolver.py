"""AWS HTTP request → IAM action resolver.

Loads botocore service models for protocol dispatch and URI path matching.
Uses iann0036/iam-dataset map.json for SDK operation → IAM action mapping.
"""

__all__ = ["ActionResolver", "load_resolver"]

import json
import logging
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from botocore.loaders import Loader

log = logging.getLogger(__name__)

_MAP_JSON_PATH = Path(__file__).parent.parent / "docs" / "map.json"


# --------------------------------------------------------------------------- #
# URI template → regex compiler
# --------------------------------------------------------------------------- #

def _compile_uri_template(request_uri: str) -> tuple[re.Pattern, list[str], frozenset[str]]:
    """Return (path_regex, [var_names], required_qs_keys) for an AWS requestUri.

    {Bucket}  → non-greedy segment  ([^/?]+?)
    {Key+}    → greedy multi-segment ([^?]+)
    Literal query string keys (e.g. "?acl", "?tagging") are returned as
    required_qs_keys so the caller can discriminate operations that share a
    path template but differ only by query string presence.
    """
    if "?" in request_uri:
        path_part, qs_part = request_uri.split("?", 1)
    else:
        path_part, qs_part = request_uri, ""
    path_part = path_part or "/"

    var_names = re.findall(r"\{([^}]+?)\+?\}", path_part)
    rx = re.escape(path_part)
    rx = re.sub(r"\\\{[^}]+?\\\+\\\}", r"([^?]+)", rx)      # {Key+} greedy
    rx = re.sub(r"\\\{.+?\\\}", r"([^/?]+?)", rx)             # {Bucket} non-greedy

    # Literal (non-variable) query string keys from the template (lowercased to
    # match against the lowercased keys we extract from the actual request).
    required_qs: frozenset[str] = frozenset()
    if qs_part:
        literal_keys = {k.lower() for k in qs_part.split("&") if "{" not in k and k}
        required_qs = frozenset(literal_keys)

    return re.compile(f"^{rx}$"), var_names, required_qs


# --------------------------------------------------------------------------- #
# Per-service compiled operation table
# --------------------------------------------------------------------------- #

class _OpEntry:
    """One compiled operation binding."""
    __slots__ = (
        "name", "http_method", "uri_regex",
        "template_qs_keys",   # literal QS keys in the URI template (e.g. {"acl"})
        "required_qs_keys",   # QS keys that must be present per shape definition
        "required_header_keys",  # lowercased header names that must be present per shape
    )

    def __init__(
        self,
        name: str,
        http_method: str,
        uri_regex: re.Pattern,
        template_qs_keys: frozenset[str],
        required_qs_keys: frozenset[str],
        required_header_keys: frozenset[str],
    ) -> None:
        self.name = name
        self.http_method = http_method
        self.uri_regex = uri_regex
        self.template_qs_keys = template_qs_keys
        self.required_qs_keys = required_qs_keys
        self.required_header_keys = required_header_keys


class _ServiceOps:
    """Pre-compiled HTTP binding table for one AWS service."""

    def __init__(self, protocol: str, ops: list[_OpEntry]) -> None:
        self.protocol = protocol
        self.ops = ops

    def match_rest(
        self,
        method: str,
        path: str,
        qs_keys: frozenset[str],
        header_keys: frozenset[str],
    ) -> str | None:
        """Return operation name for a REST request, or None."""
        candidates: list[tuple[str, int, int, int]] = []
        for op in self.ops:
            if op.http_method != method:
                continue
            if not op.uri_regex.match(path):
                continue
            # Literal template QS keys must all be present (e.g. ?acl, ?tagging)
            if not op.template_qs_keys.issubset(qs_keys):
                continue
            # Shape-required QS keys must be present (e.g. partNumber for UploadPart)
            if not op.required_qs_keys.issubset(qs_keys):
                continue
            # Shape-required header keys must be present (e.g. x-amz-copy-source for CopyObject)
            if not op.required_header_keys.issubset(header_keys):
                continue
            specificity = (
                len(op.template_qs_keys),    # literal QS template match (most specific)
                len(op.required_qs_keys),    # required QS params
                len(op.required_header_keys), # required headers
                len(op.uri_regex.pattern),   # longer path template
            )
            candidates.append((op.name, *specificity))
        if not candidates:
            return None
        candidates.sort(key=lambda c: c[1:], reverse=True)
        return candidates[0][0]


# --------------------------------------------------------------------------- #
# Service name normalisation: botocore slug → map.json SDK key prefix
# --------------------------------------------------------------------------- #

def _build_slug_to_sdk(service_sdk_mappings: dict[str, list[str]]) -> dict[str, str]:
    """Build a botocore-slug → canonical SDK service name dict from map.json."""
    result: dict[str, str] = {}
    for slug, names in service_sdk_mappings.items():
        # Prefer the first name that actually has entries in sdk_method_iam_mappings
        # (resolved at call time); store all candidates keyed by slug.
        result[slug] = names[0] if names else slug
    return result


# --------------------------------------------------------------------------- #
# Main resolver class
# --------------------------------------------------------------------------- #

class ActionResolver:
    def __init__(self, map_json_path: Path = _MAP_JSON_PATH) -> None:
        with open(map_json_path) as f:
            data = json.load(f)

        self._iam_mappings: dict[str, list[dict]] = data["sdk_method_iam_mappings"]
        self._permissionless: set[str] = set(data.get("sdk_permissionless_actions", []))
        # botocore slug → list of SDK service name candidates
        self._slug_to_sdk_candidates: dict[str, list[str]] = data.get("service_sdk_mappings", {})
        self._slug_to_sdk: dict[str, str] = _build_slug_to_sdk(self._slug_to_sdk_candidates)

        self._loader = Loader()
        self._service_ops: dict[str, _ServiceOps] = {}  # populated lazily

    # ---------------------------------------------------------------------- #
    # Public API
    # ---------------------------------------------------------------------- #

    def resolve(
        self,
        method: str,
        host: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        service_slug: str,
    ) -> list[str]:
        """Return IAM action strings for this AWS HTTP request.

        Returns [] for permissionless operations or unknown services.
        Returns ["<service>:<Operation>"] as a best-effort fallback when the
        operation can be identified but map.json has no entry.
        """
        ops = self._get_service_ops(service_slug)
        if ops is None:
            log.debug("resolver: unknown service slug %s", service_slug)
            return []

        operation = self._dispatch(ops, method, path, headers, body)
        if operation is None:
            log.debug("resolver: could not dispatch %s %s for %s", method, path, service_slug)
            return []

        return self._lookup_actions(service_slug, operation)

    # ---------------------------------------------------------------------- #
    # Service model loading (lazy, cached)
    # ---------------------------------------------------------------------- #

    def _get_service_ops(self, slug: str) -> "_ServiceOps | None":
        if slug in self._service_ops:
            return self._service_ops[slug]

        try:
            model = self._loader.load_service_model(slug, "service-2")
        except Exception:
            self._service_ops[slug] = None  # type: ignore[assignment]
            return None

        protocol = model["metadata"]["protocol"]
        ops_list: list[_OpEntry] = []

        if protocol in ("rest-json", "rest-xml"):
            shapes = model.get("shapes", {})
            for op_name, op_data in model["operations"].items():
                http = op_data.get("http", {})
                http_method = http.get("method", "POST").upper()
                uri = http.get("requestUri", "/")
                uri_regex, _, template_qs = _compile_uri_template(uri)

                # Extract required QS and header params from the input shape
                req_qs: set[str] = set()
                req_headers: set[str] = set()
                input_ref = op_data.get("input", {})
                if input_ref:
                    input_shape = shapes.get(input_ref.get("shape", ""), {})
                    shape_required = set(input_shape.get("required", []))
                    for mem_name, mem in input_shape.get("members", {}).items():
                        if mem_name not in shape_required:
                            continue
                        loc = mem.get("location", "")
                        loc_name = mem.get("locationName", mem_name).lower()
                        if loc == "querystring":
                            req_qs.add(loc_name)
                        elif loc == "header":
                            req_headers.add(loc_name)

                ops_list.append(_OpEntry(
                    name=op_name,
                    http_method=http_method,
                    uri_regex=uri_regex,
                    template_qs_keys=template_qs,
                    required_qs_keys=frozenset(req_qs),
                    required_header_keys=frozenset(req_headers),
                ))

        svc_ops = _ServiceOps(protocol, ops_list)
        self._service_ops[slug] = svc_ops
        return svc_ops

    # ---------------------------------------------------------------------- #
    # Protocol dispatch
    # ---------------------------------------------------------------------- #

    def _dispatch(
        self,
        ops: _ServiceOps,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> str | None:
        p = ops.protocol

        if p == "json":
            target = headers.get("x-amz-target") or headers.get("X-Amz-Target", "")
            if "." in target:
                return target.split(".")[-1]
            return target or None

        if p in ("query", "ec2"):
            try:
                vals = parse_qs(body.decode("utf-8", errors="replace"))
                actions = vals.get("Action") or vals.get("action")
                if actions:
                    return actions[0]
            except Exception:
                pass
            # EC2 and some query services also accept Action in query string
            parsed = urlparse(path)
            qs_vals = parse_qs(parsed.query)
            actions = qs_vals.get("Action") or qs_vals.get("action")
            if actions:
                return actions[0]
            return None

        if p in ("rest-json", "rest-xml"):
            parsed = urlparse(path)
            clean_path = parsed.path or "/"
            # Use raw split to handle bare keys like ?acl (no =value) used by S3.
            # Lowercase so they match locationName values from the shape definition.
            qs_keys = frozenset(
                k.split("=")[0].lower() for k in parsed.query.split("&") if k
            )
            header_keys = frozenset(k.lower() for k in headers)
            return ops.match_rest(method.upper(), clean_path, qs_keys, header_keys)

        # Fallback for "query" variants or unknown protocols
        log.debug("resolver: unhandled protocol %s", p)
        return None

    # ---------------------------------------------------------------------- #
    # map.json lookup
    # ---------------------------------------------------------------------- #

    def _lookup_actions(self, slug: str, operation: str) -> list[str]:
        sdk_name = self._resolve_sdk_name(slug, operation)
        if sdk_name is None:
            return []

        sdk_key = f"{sdk_name}.{operation}"

        if sdk_key in self._permissionless:
            log.debug("resolver: permissionless %s", sdk_key)
            return []

        entries = self._iam_mappings.get(sdk_key)
        if entries is not None:
            actions = [e["action"] for e in entries]
            log.debug("resolver: %s → %s", sdk_key, actions)
            return actions

        # Fallback: synthesise action name from slug + operation
        fallback = f"{slug}:{operation}"
        log.debug("resolver: no map.json entry for %s, fallback %s", sdk_key, fallback)
        return [fallback]

    def _resolve_sdk_name(self, slug: str, operation: str) -> str | None:
        """Find the SDK service name prefix used in map.json for this botocore slug."""
        candidates = self._slug_to_sdk_candidates.get(slug)
        if not candidates:
            # No entry in service_sdk_mappings — try slug as PascalCase
            pascal = "".join(w.capitalize() for w in re.split(r"[-_]", slug))
            if any(k.startswith(f"{pascal}.") for k in self._iam_mappings):
                return pascal
            log.debug("resolver: no SDK name mapping for slug %s", slug)
            return None

        # Pick the first candidate that has entries in the map
        for name in candidates:
            if any(k.startswith(f"{name}.") for k in self._iam_mappings):
                return name

        # No candidate has entries — return first anyway for fallback synthesis
        return candidates[0]


# --------------------------------------------------------------------------- #
# Module-level singleton
# --------------------------------------------------------------------------- #

_resolver: ActionResolver | None = None


def load_resolver(map_json_path: Path = _MAP_JSON_PATH) -> ActionResolver:
    """Return the module-level ActionResolver, initialising it on first call."""
    global _resolver
    if _resolver is None:
        _resolver = ActionResolver(map_json_path)
        log.info("ActionResolver loaded from %s", map_json_path)
    return _resolver
