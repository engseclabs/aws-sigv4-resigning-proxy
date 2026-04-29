# aws-sigv4-resigning-proxy

A [mitmproxy](https://mitmproxy.org/) addon that strips and re-signs AWS SigV4 requests on the fly, using credentials vended by [elhaz](https://github.com/61418/elhaz).

The proxy sits between an untrusted agent and AWS. The agent holds a dummy IAM user credential that authenticates it to the proxy. The proxy holds real IAC credentials, validates the inbound signature locally, strips it, and re-signs outbound requests with IAC credentials the agent never sees.

## Why this exists: IAM Identity Center roles are unmodifiable

AWS IAM Identity Center roles live under `/aws-reserved/` and return `UnmodifiableEntity` on any attempt to modify their trust policy. The trust policy allows only `sts:AssumeRoleWithSAML` from the SAML provider — self-assumption is blocked. This means an agent cannot directly assume an IAC role, and session policies (which require an `AssumeRole` call that the trust policy must permit) are also unreachable.

The proxy is the solution: it holds an elhaz session for the IAC role and re-signs outbound requests. The agent authenticates to the proxy, not to AWS directly.

## Dummy IAM user as credential carrier

The agent is given access keys for an IAM user with no attached policies. These keys authenticate the agent to the proxy via SigV4 but cannot call any AWS API directly.

This is intentional. If the keys appear in a prompt, a log, or an exfiltrated file, they are useless outside the proxy. Credential leakage from the agent only compromises its identity to the proxy, not its access to AWS.

## Docker isolation as the enforcement boundary

Run the proxy on the host (or in a privileged sidecar). The agent runs in a container with no host network access, no elhaz socket mount, and no IAM instance profile reachable from inside the container. The proxy is the agent's only path to AWS — isolation is a property of the environment, not a property of the agent.

## Recording and enforcement modes

The proxy supports two operating modes:

- **Recording mode**: forward all requests, log every AWS API call (service, action, resource ARN, params). Use this to observe what the agent actually does.
- **Enforcement mode**: only forward requests that match the recorded allowlist. Block everything else with a forged `AccessDenied` response that AWS SDKs handle gracefully. Optionally pause on unknown requests for human approval.

This inverts the traditional least-privilege problem: instead of authoring a policy before the agent runs, you observe real behavior and derive the allowlist from it. See [DESIGN.md](DESIGN.md) for the full architecture.

## Prerequisites

- [elhaz](https://github.com/61418/elhaz) installed and daemon running
- A named elhaz config for the role you want the agent to use
- Python 3.12

## Quickstart

```bash
# 1. Create the virtualenv
bash setup_venv.sh

# 2. Start the proxy (separate terminal)
ELHAZ_CONFIG_NAME=my-agent-role bash start_proxy.sh

# 3. Run the test
bash test_resign.sh
```

The test calls `aws sts get-caller-identity` through the proxy. The returned ARN should be the elhaz role, not whatever identity is in your shell environment.

## Files

| File | What it does |
|---|---|
| `elhaz_resign.py` | mitmproxy addon — strips inbound SigV4 headers and re-signs using elhaz credentials |
| `setup_venv.sh` | Creates a `.venv` with mitmproxy and botocore |
| `start_proxy.sh` | Starts `mitmdump` on port 8080 with the addon loaded |
| `test_resign.sh` | Runs `aws sts get-caller-identity` through the proxy to verify signing works |
| `DESIGN.md` | Full architecture and design rationale |
