#!/usr/bin/env bash
# start_proxy.sh — start iam-agent-proxy on port 8080.
#
# Run this in a separate terminal before running test_resign.sh.
# The proxy generates ~/.iam-agent-proxy/ca.pem on first run and writes
# ca_bundle to ~/.aws/config so AWS_CA_BUNDLE doesn't need to be set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SOCK_PATH="${PROXY_SOCK_PATH:-/run/proxy/creds.sock}"
SOCK_DIR="$(dirname "${SOCK_PATH}")"

# Create the socket directory if needed (no-op inside Docker where it's a volume mount)
if [[ ! -d "${SOCK_DIR}" ]]; then
    mkdir -p "${SOCK_DIR}"
fi

# Prefer the venv's Python if available
VENV_PYTHON="${SCRIPT_DIR}/venv/bin/python"
if [[ -f "${VENV_PYTHON}" ]]; then
    PYTHON="${VENV_PYTHON}"
else
    PYTHON="python3"
fi

echo "Starting iam-agent-proxy..."
echo "  Port:        8080"
echo "  CA:          ${HOME}/.iam-agent-proxy/ca.pem"
echo "  Creds sock:  ${SOCK_PATH}"
echo
echo "First run generates ${HOME}/.iam-agent-proxy/ca.pem"
echo "Press Ctrl-C to stop."
echo

exec "${PYTHON}" -m iam_agent_proxy
