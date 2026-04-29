# aws-sigv4-resigning-proxy

A [mitmproxy](https://mitmproxy.org/) addon that sits between an untrusted agent and AWS. The agent holds a proxy-issued keypair with no IAM identity. The proxy validates the inbound SigV4 signature locally, strips it, and re-signs outbound requests with real IAC credentials the agent never sees.

## Why this exists: IAM Identity Center roles are unmodifiable

AWS IAM Identity Center roles live under `/aws-reserved/` and return `UnmodifiableEntity` on any attempt to modify their trust policy. The trust policy allows only `sts:AssumeRoleWithSAML` from the SAML provider — self-assumption is blocked. Session policies (which require an `AssumeRole` call the trust policy must permit) are also unreachable.

The proxy is the workaround: it holds an [elhaz](https://github.com/61418/elhaz) session for the IAC role and re-signs outbound requests. The agent authenticates to the proxy, not to AWS directly.

## How it works

**Credential carrier** — the proxy generates fake-but-syntactically-valid AWS keypairs and vends them to agent clients over a Unix socket (`creds.sock`). There is no IAM identity behind these keys. Each socket connection gets its own distinct keypair so the proxy can tell clients apart. The agent's AWS SDK uses the keypair to sign requests; if the keypair leaks it is useless to AWS.

**Local SigV4 validation** — the proxy recomputes the HMAC-SHA256 signature from the inbound request and looks up the signing secret by `access_key_id`. Requests signed with unknown or mismatched keys are rejected with a forged `InvalidClientTokenId` 403 before any IAC credential fetch occurs.

**Docker isolation** — the agent container gets only `creds.sock` and the mitmproxy port. No elhaz socket, no IAC credentials, no host network access. The proxy is the agent's only path to AWS. Isolation is a property of the environment, not a property of the agent.

**Recording and enforcement modes** *(planned)* — see [DESIGN.md](DESIGN.md).

## Quickstart

### Prerequisites

- Docker and docker compose
- [elhaz](https://github.com/61418/elhaz) installed, daemon running, and target role added

```bash
elhaz daemon start
elhaz daemon add -n sandbox-elhaz   # or whatever role you want the agent to use
```

### Start the stack

```bash
# Build images and start proxy + agent containers
ELHAZ_CONFIG_NAME=sandbox-elhaz docker compose up -d --build
```

The proxy generates a mitmproxy CA cert on first run and persists it in the `mitm-ca` volume. The agent waits for the proxy TCP healthcheck to pass before starting.

### Run the test

```bash
docker compose exec agent bash /agent/test_resign.sh
```

Expected output:
```
=== elhaz SigV4 re-signing — Phase 1 ===
Mode: container
...
SUCCESS: The identity is an assumed-role (as expected from elhaz).
```

Or call the AWS CLI directly — the agent container has `AWS_PROFILE`, `HTTPS_PROXY`, and `AWS_CA_BUNDLE` pre-set:

```bash
docker compose exec agent aws sts get-caller-identity
docker compose exec agent aws s3 ls
```

### Tear down

```bash
docker compose down     # stops containers, keeps volumes (CA cert, etc.)
docker compose down -v  # stops containers and removes volumes
```

## How the containers are wired

```
host
├── elhaz daemon  ←─── ~/.elhaz/sock/daemon.sock (bind-mounted into proxy)
│
├── proxy container
│   ├── mitmdump :8080          — intercepts and re-signs AWS requests
│   ├── elhaz (in /opt/elhaz-venv) — fetches IAC credentials via mounted socket
│   ├── /run/proxy/creds.sock   — vends per-client proxy keypairs (named volume)
│   └── /run/mitmproxy/         — CA cert (named volume)
│
└── agent container
    ├── AWS SDK / CLI           — signs requests with proxy keypair
    ├── proxy-creds             — credential_process helper reads creds.sock
    ├── HTTPS_PROXY=proxy:8080  — routes all AWS traffic through proxy
    └── (no elhaz socket, no IAC credentials)
```

The agent is on an internal Docker bridge network. Its only internet egress is through the proxy container.

> **Note on dependencies:** mitmproxy 12.x and elhaz 0.5.x have an irreconcilable `typing-extensions` version conflict. The proxy image resolves this by installing elhaz in a separate venv (`/opt/elhaz-venv`) and symlinking its binary onto `PATH`. They never share a Python environment.

## Configuration

| Env var | Default | Description |
|---|---|---|
| `ELHAZ_CONFIG_NAME` | `sandbox-elhaz` | elhaz config name for the IAC role |
| `ELHAZ_SOCK` | `~/.elhaz/sock/daemon.sock` | Host path to the elhaz daemon socket |
| `ELHAZ_CONFIG_DIR` | `~/.elhaz/configs` | Host path to elhaz config files |
| `ELHAZ_SOCKET_PATH` | `/tmp/elhaz.sock` | Socket path inside the proxy container |
| `PROXY_SOCK_PATH` | `/run/proxy/creds.sock` | Unix socket path for credential vending |
| `PROXY_KEYPAIR_TTL` | `3600` | Proxy keypair lifetime in seconds |

Override defaults in `.env` or by prefixing `docker compose up`:

```bash
ELHAZ_CONFIG_NAME=my-agent-role docker compose up -d
```

## Local (non-Docker) usage

```bash
bash setup_venv.sh

# Terminal 1 — start the proxy (override PROXY_SOCK_PATH; /run/proxy/ requires root on macOS)
PROXY_SOCK_PATH=/tmp/proxy/creds.sock ELHAZ_CONFIG_NAME=sandbox-elhaz bash start_proxy.sh

# Terminal 2 — set up the local environment and run the test
source dev_setup.sh          # sets AWS_ACCESS_KEY_ID, HTTPS_PROXY, AWS_CA_BUNDLE
bash test_resign.sh

# Or exec a single command directly
bash dev_setup.sh aws sts get-caller-identity
```

## Files

| File | What it does |
|---|---|
| `elhaz_resign.py` | mitmproxy addon — issues per-client keypairs, validates inbound SigV4, re-signs with elhaz credentials |
| `proxy-creds` | `credential_process` helper — connects to `creds.sock` and prints the keypair JSON the AWS SDK expects |
| `docker/proxy/Dockerfile` | Proxy image — mitmproxy + botocore + pydantic; elhaz in isolated venv |
| `docker/agent/Dockerfile` | Agent image — AWS CLI + proxy-creds wired up via `credential_process` |
| `docker-compose.yml` | Wires proxy and agent together with correct volume mounts and network isolation |
| `setup_venv.sh` | Creates a local `venv/` for running without Docker |
| `start_proxy.sh` | Starts `mitmdump` locally on port 8080 |
| `dev_setup.sh` | Fetches a proxy keypair from `creds.sock` and exports `AWS_*` / `HTTPS_PROXY` env vars for local use; sourceable or pass a command to exec |
| `test_resign.sh` | Calls `aws sts get-caller-identity` and checks the ARN; assumes env is already configured (via `dev_setup.sh` locally or pre-set in Docker) |
| `DESIGN.md` | Full architecture and design rationale |
