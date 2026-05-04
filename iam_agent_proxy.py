"""
iam-agent-proxy entrypoint.

Usage:
    python iam_agent_proxy.py

On first run generates a CA cert under ~/.iam-agent-proxy/ and writes an
[profile iam-agent-proxy] section into ~/.aws/config so that any AWS tool
pointed at AWS_PROFILE=iam-agent-proxy and HTTPS_PROXY=http://localhost:8080
gets proxy-issued credentials automatically.

Both the profile section and the ca_bundle entry are removed on clean exit.

Config (env vars):
    PROXY_MODE        "record" (default) or "enforce"
    ALLOWLIST_PATH    Path to IAM policy JSON (required in enforce mode)
    ACTION_LOG_PATH   Where resolved actions are written
                      (default: ~/.iam-agent-proxy/actions.log)
"""

import configparser
import datetime
import ipaddress
import os
import signal
import sys
from pathlib import Path

_CA_DIR = Path.home() / ".iam-agent-proxy"
_CA_CERT = _CA_DIR / "ca.pem"
_CA_KEY = _CA_DIR / "ca.key"
_AWS_CONFIG = Path.home() / ".aws" / "config"
_PROXY_CREDS = Path(__file__).parent / "proxy-creds"
_SOCK_PATH = Path.home() / ".iam-agent-proxy" / "creds.sock"


def _generate_ca() -> None:
    """Generate a self-signed RSA-4096 CA cert valid for 10 years."""
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


def _write_aws_profile() -> None:
    """Write [profile iam-agent-proxy] into ~/.aws/config."""
    _AWS_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    cfg = configparser.ConfigParser()
    if _AWS_CONFIG.exists():
        cfg.read(_AWS_CONFIG)

    section = "profile iam-agent-proxy"
    if not cfg.has_section(section):
        cfg.add_section(section)

    cfg.set(section, "credential_process", f"python {_PROXY_CREDS}")
    cfg.set(section, "ca_bundle", str(_CA_CERT))

    with open(_AWS_CONFIG, "w") as f:
        cfg.write(f)


def _remove_aws_profile() -> None:
    """Remove the [profile iam-agent-proxy] section written on startup."""
    if not _AWS_CONFIG.exists():
        return
    cfg = configparser.ConfigParser()
    cfg.read(_AWS_CONFIG)
    if cfg.has_section("profile iam-agent-proxy"):
        cfg.remove_section("profile iam-agent-proxy")
        with open(_AWS_CONFIG, "w") as f:
            cfg.write(f)


def _setup_signal_handlers() -> None:
    def _cleanup(signum, frame):
        _remove_aws_profile()
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)


def main() -> None:
    if not _CA_CERT.exists() or not _CA_KEY.exists():
        _generate_ca()

    _SOCK_PATH.parent.mkdir(parents=True, exist_ok=True)

    print(f"CA cert:    {_CA_CERT}", flush=True)
    print(f"Action log: {_CA_DIR / 'actions.log'}", flush=True)
    print("Writing [profile iam-agent-proxy] to ~/.aws/config", flush=True)
    _write_aws_profile()
    _setup_signal_handlers()

    print("", flush=True)
    print("In a second terminal, run AWS commands with:", flush=True)
    print("  export AWS_PROFILE=iam-agent-proxy", flush=True)
    print("  export HTTPS_PROXY=http://localhost:8080", flush=True)
    print("", flush=True)

    try:
        # PROXY_SOCK_PATH env var picked up by core/addon.py
        os.environ.setdefault("PROXY_SOCK_PATH", str(_SOCK_PATH))
        from proxy.proxy import main as proxy_main
        proxy_main([
            "--hostname", "127.0.0.1",
            "--port", "8080",
            "--ca-cert-file", str(_CA_CERT),
            "--ca-key-file", str(_CA_KEY),
            "--ca-signing-key-file", str(_CA_KEY),
            "--plugins", "core.addon.ResignPlugin",
        ])
    finally:
        _remove_aws_profile()


if __name__ == "__main__":
    main()
