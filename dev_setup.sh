#!/usr/bin/env bash
# dev_setup.sh — configure the local environment to send AWS requests through
# the elhaz-resign proxy.
#
# Usage (sourceable):
#   source dev_setup.sh
#   aws sts get-caller-identity
#   bash test_resign.sh
#
# Usage (exec a command directly):
#   bash dev_setup.sh aws sts get-caller-identity
#
# Prerequisites:
#   - elhaz daemon running with the target role loaded
#   - ./start_proxy.sh running in a separate terminal
#   - creds.sock present at PROXY_SOCK_PATH (default: /tmp/proxy/creds.sock)
#     (use /tmp/proxy/creds.sock locally; /run/proxy/creds.sock requires root on macOS)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MITM_CA="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
PROXY="http://localhost:8080"
PROXY_CREDS="${SCRIPT_DIR}/proxy-creds"
SOCK_PATH="${PROXY_SOCK_PATH:-/tmp/proxy/creds.sock}"

# ── sanity checks ─────────────────────────────────────────────────────────────

if [[ ! -f "${MITM_CA}" ]]; then
    echo "ERROR: mitmproxy CA cert not found at ${MITM_CA}" >&2
    echo "       Run start_proxy.sh at least once to generate it." >&2
    exit 1
fi

if ! python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(2)
try:
    s.connect(('localhost', 8080))
    s.close()
except OSError:
    sys.exit(1)
" 2>/dev/null; then
    echo "ERROR: Nothing is listening on ${PROXY}." >&2
    echo "       Start the proxy first: PROXY_SOCK_PATH=${SOCK_PATH} bash start_proxy.sh" >&2
    exit 1
fi

if [[ ! -S "${SOCK_PATH}" ]]; then
    echo "ERROR: creds.sock not found at ${SOCK_PATH}" >&2
    echo "       The proxy creates it on startup. Is start_proxy.sh running?" >&2
    exit 1
fi

# ── fetch proxy-issued keypair ────────────────────────────────────────────────

CREDS_JSON=$(PROXY_SOCK_PATH="${SOCK_PATH}" "${PROXY_CREDS}")

export AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY
AWS_ACCESS_KEY_ID=$(echo "${CREDS_JSON}" | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKeyId'])")
AWS_SECRET_ACCESS_KEY=$(echo "${CREDS_JSON}" | python3 -c "import sys,json; print(json.load(sys.stdin)['SecretAccessKey'])")
unset AWS_SESSION_TOKEN 2>/dev/null || true
unset AWS_PROFILE 2>/dev/null || true

export HTTPS_PROXY="${PROXY}"
export HTTP_PROXY="${PROXY}"
export AWS_CA_BUNDLE="${MITM_CA}"

echo "Proxy environment set:" >&2
echo "  AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}" >&2
echo "  HTTPS_PROXY=${HTTPS_PROXY}" >&2
echo "  AWS_CA_BUNDLE=${AWS_CA_BUNDLE}" >&2
echo >&2

# ── exec a command if one was provided, otherwise return (for sourcing) ───────

if [[ $# -gt 0 ]]; then
    exec "$@"
fi
