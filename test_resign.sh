#!/usr/bin/env bash
# test_resign.sh — call aws sts get-caller-identity through the elhaz-resign proxy.
#
# Works in two modes:
#
#   Container mode (default when DOCKER=1 or when running inside the agent container):
#     Credentials and proxy env vars are already set in the container environment.
#     Just call the AWS CLI directly.
#
#   Local mode (default otherwise):
#     1. Fetch a proxy-issued keypair from creds.sock via proxy-creds.
#     2. Export those credentials into the environment.
#     3. Route the request through mitmproxy on localhost:8080.
#
# Prerequisites (local mode):
#   - elhaz daemon running
#   - ./start_proxy.sh running in a separate terminal
#   - creds.sock present at PROXY_SOCK_PATH (default: /run/proxy/creds.sock)
#
# Prerequisites (container mode):
#   - docker compose up -d
#   - docker compose exec agent bash test_resign.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── detect mode ───────────────────────────────────────────────────────────────

# Running inside the agent container: env vars are already set.
# Detect by checking whether AWS_CA_BUNDLE points at the mitm cert volume.
if [[ "${AWS_CA_BUNDLE:-}" == "/run/mitmproxy/mitmproxy-ca-cert.pem" ]]; then
    DOCKER=1
fi

DOCKER="${DOCKER:-0}"

echo "=== elhaz SigV4 re-signing — Phase 1 ==="
echo "Mode: $([ "${DOCKER}" = "1" ] && echo container || echo local)"
echo

# ── local mode setup ─────────────────────────────────────────────────────────

if [[ "${DOCKER}" != "1" ]]; then
    MITM_CA="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
    PROXY="http://localhost:8080"
    PROXY_CREDS="${SCRIPT_DIR}/proxy-creds"
    SOCK_PATH="${PROXY_SOCK_PATH:-/run/proxy/creds.sock}"

    if [[ ! -f "${MITM_CA}" ]]; then
        echo "ERROR: mitmproxy CA cert not found at ${MITM_CA}"
        echo "       Run mitmdump at least once to generate it, then re-run this script."
        exit 1
    fi

    if ! curl -s --proxy "${PROXY}" http://mitm.it/ &>/dev/null; then
        echo "ERROR: Nothing is listening on ${PROXY}."
        echo "       Start the proxy first: ./start_proxy.sh"
        exit 1
    fi

    if [[ ! -S "${SOCK_PATH}" ]]; then
        echo "ERROR: creds.sock not found at ${SOCK_PATH}"
        echo "       The proxy creates it on startup. Is start_proxy.sh running?"
        exit 1
    fi

    echo "Fetching proxy keypair from ${SOCK_PATH} ..."
    CREDS_JSON=$("${PROXY_CREDS}")

    export AWS_ACCESS_KEY_ID
    export AWS_SECRET_ACCESS_KEY
    AWS_ACCESS_KEY_ID=$(echo "${CREDS_JSON}" | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKeyId'])")
    AWS_SECRET_ACCESS_KEY=$(echo "${CREDS_JSON}" | python3 -c "import sys,json; print(json.load(sys.stdin)['SecretAccessKey'])")
    unset AWS_SESSION_TOKEN
    unset AWS_PROFILE

    export HTTPS_PROXY="${PROXY}"
    export HTTP_PROXY="${PROXY}"
    export AWS_CA_BUNDLE="${MITM_CA}"
fi

echo "AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:-<from AWS_PROFILE>}"
echo "HTTPS_PROXY:       ${HTTPS_PROXY:-<not set>}"
echo "AWS_CA_BUNDLE:     ${AWS_CA_BUNDLE:-<not set>}"
echo

# ── call STS ─────────────────────────────────────────────────────────────────

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
