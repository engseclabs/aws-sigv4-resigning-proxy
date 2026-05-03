# IAM Agent Proxy

![Gears of Total Recall](assets/header.png)

Agents with powerful AWS IAM credential access are a source of risk. Use IAM Agent Proxy to isolate credentials as a *credential injection proxy* and stop worrying about exfiltration through prompt injection. Then, start observing and locking down IAM permissions as you go with *least privilege guardrails*.


## Credential injection proxy

The sandboxed agent holds proxy-issued fake AWS keys with no IAM identity, and the proxy re-signs outbound requests with real credentials the agent never sees. Isolation is a property of the environment, not the agent — the agent can only exfiltrate proxy credentials.


```mermaid
graph LR
    
    agent["Agent
        Signs with fake creds"]
    proxy["Proxy
        Validates fake creds, signs with real creds"]
    elhaz["Elhaz
        Daemon with real creds"]
    aws["AWS APIs"]

    agent -- "Fake SigV4" --> proxy
    proxy -- "Socket IPC" --> elhaz
    elhaz -- "Real creds" --> proxy
    proxy -- "Real SigV4" --> aws

    classDef agentStyle fill:#dcfce7,stroke:#16a34a,color:#14532d
    classDef proxyStyle fill:#dbeafe,stroke:#2563eb,color:#1e3a8a
    classDef elhazStyle fill:#f5f5f5,stroke:#737373,color:#262626
    classDef awsStyle fill:#fef3c7,stroke:#d97706,color:#78350f

    class agent agentStyle
    class proxy proxyStyle
    class elhaz elhazStyle
    class aws awsStyle
```

## Least privilege guardrail

The hardest part of locking down an agent's IAM permissions is knowing what it actually needs. Guessing produces overly broad policies; auditing code is error-prone and misses runtime behavior. The proxy resolves every outbound AWS request to its exact IAM action(s) and logs them. Run the agent against a representative workload and you get a precise, observed permission set — not an estimate. Build and apply generated policies to lock-in behavior.

```mermaid
graph LR
    agent["Agent
        Makes AWS API calls"]
    proxy["Proxy
        Records AWS API calls to generate IAM policy"]
    policy["Policy
        Recorded/observed AWS IAM policy"]
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

## Quickstart

### Prerequisites

- Docker and Docker Compose
- [elhaz](https://github.com/61418/elhaz) installed, daemon running, and the target role added

```bash
elhaz daemon start
elhaz daemon add -n sandbox-elhaz   # or whatever elahz config the agent should use
```

### Step 1 — start the stack

Open two terminal panes. In the first, start the proxy and tail its action stream:

```bash
ELHAZ_CONFIG_NAME=sandbox-elhaz docker compose up --build proxy
```

You'll see the proxy start and log lines as requests come in. Keep this pane visible — resolved IAM actions are logged here and written to `/run/proxy/actions.log` inside the container.

### Step 2 — run an integration test (one-liner)

To verify the stack is working end-to-end, run a command directly in a throwaway agent container:

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

If you see this, credentials are flowing: proxy keypair → local SigV4 validation → elhaz re-sign → AWS. A `ServiceUnavailable` response means the proxy can't reach the elhaz daemon (check `elhaz daemon status` and that the session is listed in `elhaz daemon list`).

### Step 3 — drop into an interactive agent shell

For longer sessions, open an interactive shell in the agent container:

```bash
docker compose run --rm agent bash
```

The container has `AWS_PROFILE`, `HTTPS_PROXY`, and `AWS_CA_BUNDLE` pre-configured. Run any AWS commands and watch the proxy pane:

```bash
aws sts get-caller-identity
aws s3 ls
aws iam get-role --role-name MyRole
```

In the proxy pane you'll see lines like:

```
[14:32:01] ALLOWED  sts:GetCallerIdentity
[14:32:09] ALLOWED  s3:ListAllMyBuckets
[14:32:15] ALLOWED  iam:GetRole
```

Each line is a distinct IAM action the agent actually called — not a guess.

### Step 4 — extract the policy

When you're done running commands, generate a least-privilege policy from everything observed so far:

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
        "iam:GetRole",
        "s3:ListAllMyBuckets",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

Pipe it to a file, tighten the `Resource` fields, and it's ready to use as an IAM policy or a session policy.

### Tear down

```bash
docker compose down     # stops containers, keeps volumes (CA cert, action log)
docker compose down -v  # stops containers and removes volumes
```

## How the containers are wired

```
host
├── elhaz daemon  ←─── ~/.elhaz/sock/daemon.sock (bind-mounted into proxy)
│
├── proxy container
│   ├── mitmdump :8080          — intercepts, validates SigV4, resolves IAM actions, re-signs
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

## Configuration

| Env var | Default | Description |
|---|---|---|
| `ELHAZ_CONFIG_NAME` | `sandbox-elhaz` | elhaz config name for the IAC role |
| `ELHAZ_SOCK` | `~/.elhaz/sock/daemon.sock` | Host path to the elhaz daemon socket |
| `ELHAZ_CONFIG_DIR` | `~/.elhaz/configs` | Host path to elhaz config files |
| `ELHAZ_SOCKET_PATH` | `/tmp/elhaz.sock` | Socket path inside the proxy container |
| `PROXY_SOCK_PATH` | `/run/proxy/creds.sock` | Unix socket path for credential vending |
| `PROXY_KEYPAIR_TTL` | `3600` | Proxy keypair lifetime in seconds |
| `PROXY_MODE` | `record` | `record` (forward all) or `enforce` (check allowlist) |
| `ALLOWLIST_PATH` | *(required in enforce mode)* | Path to IAM policy JSON allowlist |

Override defaults in `.env` or by prefixing `docker compose up`:

```bash
ELHAZ_CONFIG_NAME=my-agent-role docker compose up -d
```

## Appendix: why IAM Identity Center roles require a proxy

AWS IAM Identity Center roles live under `/aws-reserved/` and return `UnmodifiableEntity` on any attempt to modify their trust policy. The trust policy allows only `sts:AssumeRoleWithSAML` from the SAML provider — self-assumption is blocked. Session policies (which require an `AssumeRole` call the trust policy must permit) are also unreachable.

The proxy is the workaround: it holds an elhaz session for the IAC role and re-signs outbound requests. The agent authenticates to the proxy, not to AWS directly.

See [DESIGN.md](./DESIGN.md) for the full architecture and design rationale.
