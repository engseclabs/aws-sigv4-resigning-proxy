# aws-sigv4-resigning-proxy

A [mitmproxy](https://mitmproxy.org/) addon that strips and re-signs AWS SigV4 requests on the fly, using credentials vended by [elhaz](https://github.com/61418/elhaz).

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
