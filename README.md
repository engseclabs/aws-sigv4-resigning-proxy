# IAM Agent Proxy

> Isolate credentials as a *credential injection proxy* and stop worrying about exfiltration through prompt injection.

> Then, observe and lockdown IAM permissions with *least privilege guardrails*.

![Gears of Total Recall](assets/header.png)

## Credential injection proxy

**Agent** uses fake AWS keys and the **Proxy** re-signs outbound requests with real ones.


```mermaid
graph LR
    
    agent["Agent
    Signs with fake creds"]
    proxy["Proxy
    Validates fake creds and then signs with real creds"]
    aws["AWS APIs"]

    agent -- "Fake SigV4" --> proxy
    proxy -- "Real SigV4 (boto3)" --> aws

    classDef agentStyle fill:#dcfce7,stroke:#16a34a,color:#14532d
    classDef proxyStyle fill:#dbeafe,stroke:#2563eb,color:#1e3a8a
    classDef awsStyle fill:#fef3c7,stroke:#d97706,color:#78350f

    class agent agentStyle
    class proxy proxyStyle
    class aws awsStyle
```

## Least privilege guardrails

**Proxy** resolves every outbound AWS request to IAM action and logs them. **Agent** runs a representative workload, builds observed **Policy** which is applied by Proxy to lock-in behavior.

```mermaid
graph LR
    agent["Agent
    Makes AWS API calls"]
    proxy["Proxy
    Records actions and enforces policy"]
    policy["Policy
    Emulated IAM evaluation"]
    aws["AWS APIs"]

    agent -- "Request" --> proxy
    proxy -- "Response" --> agent
    proxy -- "Check" --> policy
    policy -- "Deny" --> proxy
    proxy -- "Allowed call" --> aws

    classDef agentStyle fill:#dcfce7,stroke:#16a34a,color:#14532d
    classDef proxyStyle fill:#dbeafe,stroke:#2563eb,color:#1e3a8a
    classDef policyStyle fill:#f5f5f5,stroke:#737373,color:#262626
    classDef awsStyle fill:#fef3c7,stroke:#d97706,color:#78350f

    class agent agentStyle
    class proxy proxyStyle
    class policy policyStyle
    class aws awsStyle
```

## Quickstart (native — no Docker)

### Prerequisites

- Python 3.12
- AWS credentials on the host (any standard source: `~/.aws/credentials`, instance profile, environment variables, SSO, etc.)

```bash
bash setup_venv.sh
```

This creates `venv/` and installs `proxy.py`, `boto3`, `botocore`, `cryptography`, and `pydantic` — no other dependencies needed.

### Step 1 — start the proxy

```bash
bash start_proxy.sh
```

On first run the proxy generates `~/.iam-agent-proxy/ca.pem` and writes `ca_bundle = ~/.iam-agent-proxy/ca.pem` into `[default]` in `~/.aws/config`. This means `AWS_CA_BUNDLE` does not need to be set manually. The entry is removed on clean exit (Ctrl-C).

### Step 2 — configure your shell

In a second terminal:

```bash
source dev_setup.sh
```

This fetches a proxy-issued keypair, sets `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `HTTPS_PROXY`, and `HTTP_PROXY`. No `AWS_CA_BUNDLE` needed — the proxy already wrote it to `~/.aws/config`.

### Step 3 — make AWS calls

```bash
aws sts get-caller-identity
aws s3 ls
```

In the proxy terminal you'll see lines like:

```
[14:32:01] ALLOWED  sts:GetCallerIdentity
[14:32:09] ALLOWED  s3:ListAllMyBuckets
```

### Step 4 — extract the policy

```bash
get-policy
```

Output:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProxyRecordedActions",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Quickstart (Docker — with elhaz)

The Docker path uses [elhaz](https://github.com/61418/elhaz) as the upstream credential source instead of boto3. This is useful when the real credentials live in an IAM Identity Center role managed by elhaz.

### Prerequisites

- Docker and Docker Compose
- [elhaz](https://github.com/61418/elhaz) installed, daemon running, and the target role added

```bash
elhaz daemon start
elhaz daemon add -n sandbox-elhaz   # or whatever elhaz config the agent should use
```

### Start the stack

```bash
ELHAZ_CONFIG_NAME=sandbox-elhaz docker compose up --build proxy
```

### Run an integration test

```bash
docker compose run --rm agent aws sts get-caller-identity
```

Expected output:

```json
{
    "UserId": "AROAEXAMPLE:boto3-refresh-session",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/YourRole/boto3-refresh-session"
}
```

### Drop into an interactive agent shell

```bash
docker compose run --rm agent bash
```

The container has `AWS_PROFILE`, `HTTPS_PROXY`, and `AWS_CA_BUNDLE` pre-configured.

### Extract the policy

```bash
get-policy
```

### Tear down

```bash
docker compose down     # stops containers, keeps volumes (CA cert, action log)
docker compose down -v  # stops containers and removes volumes
```

---

## How the native path works

```
~/.iam-agent-proxy/
  ca.pem     # CA cert generated on first run; trusted by the system/AWS SDK via ~/.aws/config
  ca.key     # CA private key

~/.aws/config
  [default]
  ca_bundle = ~/.iam-agent-proxy/ca.pem   # written on startup, removed on clean exit
```

The proxy runs as a single Python process — no separate venvs, no subprocess dependencies. `proxy.py` handles TLS interception using the generated CA; `boto3` supplies real credentials via the standard credential provider chain.

## How the Docker path works

```
host
├── elhaz daemon  ←─── ~/.elhaz/sock/daemon.sock (bind-mounted into proxy)
│
├── proxy container
│   ├── proxy.py :8080          — intercepts, validates SigV4, resolves IAM actions, re-signs
│   ├── elhaz (in /opt/elhaz-venv) — fetches IAC credentials via mounted socket
│   ├── /run/proxy/creds.sock   — vends per-client proxy keypairs (named volume)
│   └── /run/proxy/ca/          — CA cert (named volume)
│
└── agent container
    ├── AWS SDK / CLI           — signs requests with proxy keypair
    ├── proxy-creds             — credential_process helper reads creds.sock
    ├── HTTPS_PROXY=proxy:8080  — routes all AWS traffic through proxy
    └── (no elhaz socket, no IAC credentials)
```

The agent is on an internal Docker bridge network. Its only internet egress is through the proxy container.

## Configuration

| Env var | Default | Description |
|---|---|---|
| `PROXY_SOCK_PATH` | `/run/proxy/creds.sock` | Unix socket path for credential vending |
| `PROXY_KEYPAIR_TTL` | `3600` | Proxy keypair lifetime in seconds |
| `PROXY_MODE` | `record` | `record` (forward all) or `enforce` (check allowlist) |
| `ALLOWLIST_PATH` | *(required in enforce mode)* | Path to IAM policy JSON allowlist |
| `ACTION_LOG_PATH` | `/run/proxy/actions.log` | Where resolved actions are written |

**Docker-only env vars** (elhaz credential source):

| Env var | Default | Description |
|---|---|---|
| `ELHAZ_CONFIG_NAME` | `sandbox-elhaz` | elhaz config name for the IAC role |
| `ELHAZ_SOCK` | `~/.elhaz/sock/daemon.sock` | Host path to the elhaz daemon socket |
| `ELHAZ_CONFIG_DIR` | `~/.elhaz/configs` | Host path to elhaz config files |
| `ELHAZ_SOCKET_PATH` | `/tmp/elhaz.sock` | Socket path inside the proxy container |
