#!/usr/bin/env bash
# test_resign.sh — run aws sts get-caller-identity through the elhaz-resign proxy
# with no ambient AWS credentials, to verify SigV4 re-signing is working.
#
# Prerequisites:
#   - poc/venv activated (or mitmdump / aws / python on PATH with deps installed)
#   - elhaz daemon running
#   - mitmdump already listening on port 8080 with elhaz_resign.py loaded
#     (run ./start_proxy.sh in a separate terminal first)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MITM_CA="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
PROXY="http://localhost:8080"

echo "=== elhaz SigV4 re-signing PoC ==="
echo

# ── sanity checks ───────────────────────────────────────────────────────────
if [[ ! -f "${MITM_CA}" ]]; then
    echo "ERROR: mitmproxy CA cert not found at ${MITM_CA}"
    echo "       Run mitmdump at least once to generate the cert, then re-run this script."
    exit 1
fi

if ! curl -s --proxy "${PROXY}" http://mitm.it/ &>/dev/null; then
    echo "ERROR: Nothing is listening on ${PROXY}."
    echo "       Start the proxy first: ./start_proxy.sh"
    exit 1
fi

# ── supply placeholder credentials + proxy ──────────────────────────────────
# The AWS CLI refuses to build any request if credentials are completely absent.
# We give it syntactically valid placeholder values so it constructs and signs a
# request; the proxy then strips those headers and re-signs with elhaz creds
# before the request ever reaches AWS. The placeholder values never reach AWS.
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7PLACEHOLDER"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYPLACEHOLDER"
unset AWS_SESSION_TOKEN
unset AWS_PROFILE

export HTTPS_PROXY="${PROXY}"
export HTTP_PROXY="${PROXY}"
export AWS_CA_BUNDLE="${MITM_CA}"

echo "HTTPS_PROXY=${HTTPS_PROXY}"
echo "AWS_CA_BUNDLE=${AWS_CA_BUNDLE}"
echo

# ── call STS ────────────────────────────────────────────────────────────────
echo "Calling aws sts get-caller-identity ..."
RESPONSE=$(aws sts get-caller-identity --output json 2>&1) || {
    echo "FAILED — raw output:"
    echo "${RESPONSE}"
    exit 1
}

echo "${RESPONSE}" | python3 -m json.tool
echo

# ── verify the ARN belongs to elhaz role, not ambient SSO ───────────────────
ARN=$(echo "${RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])")
echo "Returned ARN: ${ARN}"

if echo "${ARN}" | grep -qi "assumed-role"; then
    echo "SUCCESS: The identity is an assumed-role (as expected from elhaz)."
else
    echo "WARNING: ARN does not look like an assumed-role. Check your elhaz config."
fi
