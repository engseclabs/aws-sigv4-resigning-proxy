FROM python:3.12-slim

# mitmproxy 12.2.2 requires typing-extensions<=4.14; elhaz 0.5.1 requires
# pydantic>=2.12.5 which requires typing-extensions>=4.14.1 — irreconcilable.
# Install them in separate venvs: elhaz is only called as a subprocess so it
# doesn't need to share the mitmproxy Python environment.
RUN pip install --no-cache-dir mitmproxy==12.2.2 botocore pydantic && \
    python -m venv /opt/elhaz-venv && \
    /opt/elhaz-venv/bin/pip install --no-cache-dir elhaz==0.5.1 && \
    ln -s /opt/elhaz-venv/bin/elhaz /usr/local/bin/elhaz

WORKDIR /proxy

COPY elhaz_resign.py .
COPY proxy/ proxy/
COPY docs/map.json docs/map.json

ENV PROXY_SOCK_PATH=/run/proxy/creds.sock
ENV ELHAZ_SOCKET_PATH=/tmp/elhaz.sock

EXPOSE 8080

CMD ["sh", "-c", \
  "mkdir -p /run/proxy && \
   mitmdump \
     --listen-port 8080 \
     --scripts /proxy/elhaz_resign.py \
     --set confdir=/run/mitmproxy"]
