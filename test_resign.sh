#!/usr/bin/env bash
# test_resign.sh — call aws sts get-caller-identity through the elhaz-resign proxy
# and verify the returned ARN belongs to the elhaz IAC role.
#
# Assumes the environment is already configured:
#   - AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (or AWS_PROFILE) set to proxy-issued creds
#   - HTTPS_PROXY pointing at the proxy
#   - AWS_CA_BUNDLE pointing at the mitmproxy CA cert
#
# In Docker:   docker compose exec agent bash /agent/test_resign.sh
# Locally:     source dev_setup.sh && bash test_resign.sh
#              (or: eval "$(bash dev_setup.sh --export)" && bash test_resign.sh)

set -euo pipefail

echo "=== elhaz SigV4 re-signing — Phase 1 ==="
echo "AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:-<from AWS_PROFILE>}"
echo "HTTPS_PROXY:       ${HTTPS_PROXY:-<not set>}"
echo "AWS_CA_BUNDLE:     ${AWS_CA_BUNDLE:-<not set>}"
echo

echo "Calling aws sts get-caller-identity ..."
RESPONSE=$(aws sts get-caller-identity --output json 2>&1) || {
    echo "FAILED — raw output:"
    echo "${RESPONSE}"
    exit 1
}

echo "${RESPONSE}" | python3 -m json.tool
echo

ARN=$(echo "${RESPONSE}" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])")
echo "Returned ARN: ${ARN}"

if echo "${ARN}" | grep -qi "assumed-role"; then
    echo "SUCCESS: The identity is an assumed-role (as expected from elhaz)."
else
    echo "WARNING: ARN does not look like an assumed-role. Check your elhaz config."
fi
