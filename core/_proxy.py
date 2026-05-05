"""iam-agent-proxy entrypoint — installed as the `iam-agent-proxy` command."""

import argparse
import configparser
import datetime
import ipaddress
import json
import os
import signal
import sys
from pathlib import Path

_CA_DIR = Path.home() / ".iam-agent-proxy"
_CA_CERT = _CA_DIR / "ca.pem"
_CA_KEY = _CA_DIR / "ca.key"
_AWS_CONFIG = Path.home() / ".aws" / "config"
_SOCK_PATH = _CA_DIR / "creds.sock"
_ACTION_LOG = Path(
    os.environ.get("ACTION_LOG_PATH", str(_CA_DIR / "actions.log"))
)


# --------------------------------------------------------------------------- #
# CA cert
# --------------------------------------------------------------------------- #

def _generate_ca() -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    _CA_DIR.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    _CA_KEY.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    _CA_KEY.chmod(0o600)

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "iam-agent-proxy CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "iam-agent-proxy"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    _CA_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Generated CA cert: {_CA_CERT}", flush=True)


# --------------------------------------------------------------------------- #
# ~/.aws/config management
# --------------------------------------------------------------------------- #

def _write_aws_profile() -> None:
    _AWS_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    cfg = configparser.ConfigParser()
    if _AWS_CONFIG.exists():
        cfg.read(_AWS_CONFIG)

    section = "profile iam-agent-proxy"
    if not cfg.has_section(section):
        cfg.add_section(section)

    # Use the absolute path to proxy-creds so ~/.aws/config works outside the venv
    proxy_creds_bin = Path(sys.executable).parent / "proxy-creds"
    cfg.set(section, "credential_process", str(proxy_creds_bin))
    cfg.set(section, "ca_bundle", str(_CA_CERT))

    with open(_AWS_CONFIG, "w") as f:
        cfg.write(f)


def _remove_aws_profile() -> None:
    if not _AWS_CONFIG.exists():
        return
    cfg = configparser.ConfigParser()
    cfg.read(_AWS_CONFIG)
    if cfg.has_section("profile iam-agent-proxy"):
        cfg.remove_section("profile iam-agent-proxy")
        with open(_AWS_CONFIG, "w") as f:
            cfg.write(f)


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #

def _cmd_start() -> None:
    if not _CA_CERT.exists() or not _CA_KEY.exists():
        _generate_ca()

    _SOCK_PATH.parent.mkdir(parents=True, exist_ok=True)

    print(f"CA cert:    {_CA_CERT}", flush=True)
    print(f"Action log: {_ACTION_LOG}", flush=True)
    print("Writing [profile iam-agent-proxy] to ~/.aws/config", flush=True)
    _write_aws_profile()

    def _cleanup(signum, frame):
        _remove_aws_profile()
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    print("", flush=True)
    print("In a second terminal, run AWS commands with:", flush=True)
    print("  export AWS_PROFILE=iam-agent-proxy", flush=True)
    print("  export HTTPS_PROXY=http://localhost:8080", flush=True)
    print("", flush=True)

    try:
        import ssl
        import core.addon as _addon
        from core.credentials import CredentialStore, start_creds_server
        from proxy.proxy import main as proxy_main

        # Start the creds server in the parent before proxy.py spawns workers.
        # Workers call fetch_store_from_socket() in _ensure_initialized() to
        # get the same keypair — no env vars, no files, pure IPC over the socket.
        _store = CredentialStore()
        start_creds_server(_SOCK_PATH, _store)

        system_ca_bundle = ssl.get_default_verify_paths().cafile or "/etc/ssl/cert.pem"
        _CERT_DIR = _CA_DIR / "certificates"
        _CERT_DIR.mkdir(parents=True, exist_ok=True)

        sys.argv = [
            "proxy",
            "--hostname", "127.0.0.1",
            "--port", "8080",
            "--ca-cert-file", str(_CA_CERT),
            "--ca-key-file", str(_CA_KEY),
            "--ca-signing-key-file", str(_CA_KEY),
            "--ca-cert-dir", str(_CERT_DIR),
            "--ca-file", system_ca_bundle,
            "--plugins", "core.addon.ResignPlugin",
        ]
        proxy_main()
    finally:
        _remove_aws_profile()


def _cmd_policy() -> None:
    if not _ACTION_LOG.exists():
        print(
            f"No action log found at {_ACTION_LOG}\n"
            "Make sure the proxy is running and you have made some AWS calls.",
            file=sys.stderr,
        )
        sys.exit(1)

    actions = sorted({
        line.strip()
        for line in _ACTION_LOG.read_text().splitlines()
        if line.strip()
    })

    if not actions:
        print("Action log is empty. Run some AWS commands first.", file=sys.stderr)
        sys.exit(1)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ProxyRecordedActions",
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*",
            }
        ],
    }
    print(json.dumps(policy, indent=2))


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="iam-agent-proxy",
        description="AWS credential injection proxy with least-privilege recording.",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("start", help="Start the proxy (default when no subcommand given)")
    sub.add_parser("policy", help="Print the observed IAM policy from the action log")

    args = parser.parse_args()

    if args.command == "policy":
        _cmd_policy()
    else:
        # default: start (also handles explicit "start")
        _cmd_start()
