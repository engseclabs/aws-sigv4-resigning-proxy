#!/usr/bin/env bash
# start_proxy.sh — start mitmdump with the elhaz_resign addon on port 8080.
#
# Run this in a separate terminal before running test_resign.sh.
# The proxy generates ~/.mitmproxy/mitmproxy-ca-cert.pem on first run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADDON="${SCRIPT_DIR}/elhaz_resign.py"

if [[ ! -f "${ADDON}" ]]; then
    echo "ERROR: addon not found at ${ADDON}"
    exit 1
fi

# Prefer the venv's mitmdump if available
VENV_MITMDUMP="${SCRIPT_DIR}/venv/bin/mitmdump"
if [[ -f "${VENV_MITMDUMP}" ]]; then
    MITMDUMP="${VENV_MITMDUMP}"
else
    MITMDUMP="mitmdump"
fi

SOCK_PATH="${PROXY_SOCK_PATH:-/run/proxy/creds.sock}"
SOCK_DIR="$(dirname "${SOCK_PATH}")"

# Create the socket directory if needed (no-op inside Docker where it's a volume mount)
if [[ ! -d "${SOCK_DIR}" ]]; then
    mkdir -p "${SOCK_DIR}"
fi

echo "Starting mitmproxy with elhaz_resign addon..."
echo "  Addon:       ${ADDON}"
echo "  Port:        8080"
echo "  Config:      ${ELHAZ_CONFIG_NAME:-sandbox-elhaz}"
echo "  CA:          ${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
echo "  Creds sock:  ${SOCK_PATH}"
echo
echo "First run generates ${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
echo "Press Ctrl-C to stop."
echo

exec "${MITMDUMP}" \
    --listen-port 8080 \
    --scripts "${ADDON}" \
    --set confdir="${HOME}/.mitmproxy"
