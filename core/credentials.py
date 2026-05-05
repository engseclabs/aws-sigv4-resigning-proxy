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
    """Single shared keypair for the proxy lifetime.

    Lives entirely in memory — no files, no env vars. Because proxy.py runs
    in threaded mode, plugin instances share this object directly.  The creds
    socket serves the same keypair to every client that connects.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cred: ClientCred = self._generate()
        log.info(
            "Issued proxy keypair access_key_id=%s expiry=%s",
            self._cred.access_key_id,
            self._cred.expiry,
        )

    def _generate(self) -> ClientCred:
        return ClientCred(
            access_key_id=_new_access_key_id(),
            secret_access_key=secrets.token_hex(32),
            expiry=datetime.now(timezone.utc) + timedelta(seconds=PROXY_KEYPAIR_TTL),
        )

    def issue(self) -> ClientCred:
        """Return the current keypair (same for every caller)."""
        with self._lock:
            return self._cred

    def valid_secrets_for(self, access_key_id: str) -> list[str] | None:
        """Return [secret] if access_key_id matches the current keypair, else None."""
        with self._lock:
            if access_key_id == self._cred.access_key_id:
                return [self._cred.secret_access_key]
        return None


# --------------------------------------------------------------------------- #
# Unix socket credential server
# --------------------------------------------------------------------------- #

def _prepare_socket_path(sock_path: Path) -> bool:
    """Remove a stale socket file if present.

    Returns True if the caller should proceed to bind, False if a live server
    is already listening there (another worker beat us to it — skip quietly).
    """
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    if not sock_path.exists():
        return True
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(str(sock_path))
        # A live server is already bound — another worker owns it.
        return False
    except ConnectionRefusedError:
        sock_path.unlink()
        return True
    except FileNotFoundError:
        return True
    finally:
        probe.close()


def _serve_creds(sock_path: Path, store: CredentialStore) -> None:
    """Serve the shared keypair to every client that connects (blocking)."""
    if not _prepare_socket_path(sock_path):
        log.debug("Credential server already running at %s, skipping", sock_path)
        return

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


def fetch_store_from_socket(sock_path: Path) -> CredentialStore:
    """Fetch the keypair from the parent's creds socket and return a read-only store.

    Used by worker processes that can't share memory with the parent — they
    connect once, get the keypair, and wrap it in a CredentialStore so the
    rest of the validation logic stays unchanged.
    """
    import json
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5.0)
        s.connect(str(sock_path))
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    payload = json.loads(data)
    store = CredentialStore.__new__(CredentialStore)
    store._lock = threading.Lock()
    store._cred = ClientCred(
        access_key_id=payload["AccessKeyId"],
        secret_access_key=payload["SecretAccessKey"],
        expiry=datetime.fromisoformat(payload["Expiration"]),
    )
    log.debug("Worker fetched keypair access_key_id=%s from socket", store._cred.access_key_id)
    return store
