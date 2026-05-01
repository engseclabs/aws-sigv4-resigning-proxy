FROM python:3.12-slim

# mitmproxy 12.2.2 requires typing-extensions<=4.14; elhaz 0.5.1 requires
# pydantic>=2.12.5 which requires typing-extensions>=4.14.1 — irreconcilable.
# Install them in separate venvs: elhaz is only called as a subprocess so it
# doesn't need to share the mitmproxy Python environment.
RUN pip install --no-cache-dir mitmproxy==12.2.2 botocore pydantic && \
    python -m venv /opt/elhaz-venv && \
    /opt/elhaz-venv/bin/pip install --no-cache-dir elhaz==0.5.1 && \
    ln -s /opt/elhaz-venv/bin/elhaz /usr/local/bin/elhaz

# Install iamlive (CSM listener — records agent AWS calls as an IAM policy)
ARG IAMLIVE_VERSION=1.1.28
RUN apt-get update -qq && apt-get install -y --no-install-recommends curl ca-certificates && \
    curl -fsSL "https://github.com/iann0036/iamlive/releases/download/v${IAMLIVE_VERSION}/iamlive_${IAMLIVE_VERSION}_linux_amd64.tar.gz" \
      | tar -xz -C /usr/local/bin iamlive && \
    apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /proxy

COPY elhaz_resign.py .
COPY proxy/ proxy/

ENV PROXY_SOCK_PATH=/run/proxy/creds.sock
ENV ELHAZ_SOCKET_PATH=/tmp/elhaz.sock

EXPOSE 8080

# Start iamlive in CSM mode (background), then mitmproxy (foreground).
# iamlive listens on UDP 0.0.0.0:31000 so the agent container can reach it
# over the shared proxy-net bridge. Policy output goes to stdout (visible via
# docker compose logs proxy) on every API call.
CMD ["sh", "-c", \
  "mkdir -p /run/proxy && \
   iamlive \
     --mode csm \
     --host 0.0.0.0 \
     --sort-alphabetical \
     --force-wildcard-resource \
     >/proc/1/fd/1 2>&1 & \
   mitmdump \
     --listen-port 8080 \
     --scripts /proxy/elhaz_resign.py \
     --set confdir=/run/mitmproxy"]
