# aws-sigv4-resigning-proxy

Proof of concept: a [mitmproxy](https://mitmproxy.org/) addon that strips and re-signs AWS SigV4 requests on the way out, using credentials vended by [elhaz](https://github.com/61418/elhaz). The agent holds placeholder credentials that are structurally inert outside the proxy; the proxy holds the real signing material.

Companion to the EngSec Labs post: [Re-signing AWS at the proxy layer for AI agents](https://engseclabs.com/blog/aws-sigv4-resigning-proxy/).

---

## Why

The credential-injection proxy pattern (agent sets `HTTPS_PROXY`, proxy swaps placeholder keys for real ones) works well for most APIs. AWS doesn't work this way. SigV4 binds the credential to the request: the signature is computed over the HTTP method, path, query string, host, timestamp, body hash, and signed-headers list, using a key derived from the secret access key through a chain of HMACs. Swapping one signed header for another produces a request AWS rejects.

The fix is to strip the inbound signature and re-sign from scratch using credentials the proxy holds. That's what this addon does.

## Prerequisites

- [elhaz](https://github.com/61418/elhaz) installed and daemon running
- A named elhaz config for the role you want the agent to use
- Python 3.12
- AWS CLI (for testing)

## Setup

```bash
# 1. Create a venv with mitmproxy and botocore
bash setup_venv.sh

# 2. Start the proxy (in a separate terminal)
ELHAZ_CONFIG_NAME=my-agent-role bash start_proxy.sh

# 3. Run the test
bash test_resign.sh
```

`start_proxy.sh` starts `mitmdump` on port 8080. On first run, mitmproxy generates a CA cert at `~/.mitmproxy/mitmproxy-ca-cert.pem`. The test script sets `AWS_CA_BUNDLE` to that cert and `HTTPS_PROXY` to the local proxy, then calls `aws sts get-caller-identity`. The returned ARN should be the elhaz role, not whatever identity is in your shell environment.

## The placeholder credential constraint

The AWS CLI and SDK refuse to build a request at all without credentials in the environment. Supply syntactically valid placeholders so the SDK proceeds:

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7PLACEHOLDER
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYPLACEHOLDER
```

The addon strips these headers entirely and re-signs with elhaz credentials before the request leaves the proxy. The placeholders never reach AWS.

## How the addon works

Three pieces:

**`parse_aws_host(host)`** — extracts `(service, region)` from an AWS hostname. Handles global endpoints (`sts.amazonaws.com`, `s3.amazonaws.com`), regional endpoints (`s3.us-west-2.amazonaws.com`, `ec2.eu-west-1.amazonaws.com`), and virtual-hosted S3 buckets (`my-bucket.s3.ap-southeast-1.amazonaws.com`). Patterns are ordered most-specific to least-specific.

**`ElhazCredentialCache`** — calls `elhaz export --format credential-process -n <config>` and caches the result. Refreshes when less than 5 minutes remain on the session.

**`ElhazResignAddon.request()`** — the mitmproxy hook. Strips `Authorization`, `X-Amz-Date`, `X-Amz-Security-Token`, and `X-Amz-Content-SHA256`. Fetches credentials from the cache. Builds a `botocore.AWSRequest` and runs `SigV4Auth.add_auth()`. Writes the resulting headers back onto the intercepted flow.

The credential resolution side is swappable. elhaz is used here because it was already on hand, but aws-vault, a `credential_process` entry, or any other mechanism that produces fresh AWS credentials would work in its place.

## What the proxy position gets you

Once the proxy is the signer:

- **Per-call session policies**: the proxy can call `AssumeRole` with an inline session policy scoped to each outbound request (read-only, single bucket, single API action). The agent has no way to broaden the scope because it has no signing material.
- **Pre-authorization audit**: the proxy sees every request before AWS does, including calls the proxy itself denies. CloudTrail only shows what AWS authorized. The proxy can show what the agent attempted.
- **Policy enforcement outside IAM**: rate limits, time-of-day restrictions, request shape allow-lists — expressible in the proxy without touching IAM.

## Known gaps

- SigV4a (used for multi-region access points) is not handled
- Streaming payload signing for large S3 uploads is not handled
- Response inspection is not implemented

This is a proof of concept. The point is to show the strip-and-resign shape works, not to ship a production tool.

## Related

- [elhaz](https://github.com/61418/elhaz) — local AWS credential broker daemon
- [aws-sigv4-proxy](https://github.com/awslabs/aws-sigv4-proxy) — AWS-published signing proxy (for unsigned callers)
- [OneCLI](https://github.com/onecli/onecli) — credential-injection proxy for non-AWS APIs
- [EngSec Labs: AWS Credential Isolation for Local AI Agents](https://engseclabs.com/blog/agent-credential-isolation/) — the Unix socket approach this builds on
