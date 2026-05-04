#!/usr/bin/env bash
# setup_venv.sh — create a Python 3.12 venv with proxy.py + boto3 + cryptography.
# Run once before start_proxy.sh / test_resign.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${SCRIPT_DIR}/venv"
PYTHON="/opt/homebrew/bin/python3.12"

if [[ ! -x "${PYTHON}" ]]; then
    echo "ERROR: Python 3.12 not found at ${PYTHON}"
    echo "       Install with: brew install python@3.12"
    exit 1
fi

if [[ -d "${VENV}" ]]; then
    echo "venv already exists at ${VENV} — skipping creation."
    echo "To recreate: rm -rf ${VENV} && bash setup_venv.sh"
else
    echo "Creating venv with ${PYTHON}..."
    "${PYTHON}" -m venv "${VENV}"
fi

echo "Installing/upgrading dependencies..."
"${VENV}/bin/pip" install --quiet --upgrade pip
"${VENV}/bin/pip" install --quiet "proxy.py" botocore boto3 cryptography pydantic

echo
echo "Done. To activate:"
echo "  source ${VENV}/bin/activate"
echo
echo "Or run the proxy directly:"
echo "  bash ${SCRIPT_DIR}/start_proxy.sh"
