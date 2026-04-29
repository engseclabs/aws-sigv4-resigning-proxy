"""Per-client credential store and Unix socket credential server."""

__all__ = ["CredentialStore", "start_creds_server"]

import logging
import os
import secrets
import socket
import string
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .exceptions import ProxyError
from .models import ClientCred, CredentialPayload

log = logging.getLogger(__name__)

_AK_PREFIX = "AKIAPROXY"
_AK_ALPHABET = string.ascii_uppercase + string.digits

PROXY_KEYPAIR_TTL = int(os.environ.get("PROXY_KEYPAIR_TTL", "3600"))


def _new_access_key_id() -> str:
    suffix = "".join(secrets.choice(_AK_ALPHABET) for _ in range(20 - len(_AK_PREFIX)))
    return _AK_PREFIX + suffix


# --------------------------------------------------------------------------- #
# Credential store
# --------------------------------------------------------------------------- #

class CredentialStore:
    """Issues and tracks one unique keypair per socket connection."""

    def __init__(self) -> None:
        self._store: dict[str, ClientCred] = {}
        self._lock = threading.Lock()

    def issue(self) -> ClientCred:
        cred = ClientCred(
            access_key_id=_new_access_key_id(),
            secret_access_key=secrets.token_hex(32),
            expiry=datetime.now(timezone.utc) + timedelta(seconds=PROXY_KEYPAIR_TTL),
        )
        with self._lock:
            self._store[cred.access_key_id] = cred
        log.info("Issued proxy keypair access_key_id=%s expiry=%s", cred.access_key_id, cred.expiry)
        return cred

    def valid_secrets_for(self, access_key_id: str) -> list[str] | None:
        """Return [current_secret, prev_secret?] for the given key, or None if unknown."""
        with self._lock:
            cred = self._store.get(access_key_id)
        if cred is None:
            return None
        return [cred.secret_access_key, *([cred.prev_secret] if cred.prev_secret else [])]


# --------------------------------------------------------------------------- #
# Unix socket credential server
# --------------------------------------------------------------------------- #

def _prepare_socket_path(sock_path: Path) -> None:
    """Remove a stale socket file if present; raise if a live server is bound there."""
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    if not sock_path.exists():
        return
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(str(sock_path))
        probe.close()
        raise ProxyError(f"A server is already listening on {sock_path}")
    except ConnectionRefusedError:
        sock_path.unlink()
    except FileNotFoundError:
        pass
    finally:
        probe.close()


def _serve_creds(sock_path: Path, store: CredentialStore) -> None:
    """Issue a fresh keypair per connection and send it to the client (blocking)."""
    _prepare_socket_path(sock_path)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
        srv.bind(str(sock_path))
        sock_path.chmod(0o600)
        srv.listen()
        log.info("Credential socket listening at %s", sock_path)
        while True:
            try:
                conn, _ = srv.accept()
                with conn:
                    payload = store.issue().to_payload()
                    conn.sendall(payload.model_dump_json().encode())
            except Exception as exc:
                log.error("creds.sock error: %s", exc)


def start_creds_server(sock_path: Path, store: CredentialStore) -> None:
    t = threading.Thread(target=_serve_creds, args=(sock_path, store), daemon=True)
    t.start()
