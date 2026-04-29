FROM python:3.12-slim

RUN pip install --no-cache-dir mitmproxy botocore pydantic elhaz==0.5.1

WORKDIR /proxy

COPY elhaz_resign.py .

# Generate the mitmproxy CA on first run; persist it via a named volume.
# The socket directory is created by start_proxy.sh or by the entrypoint below.
ENV PROXY_SOCK_PATH=/run/proxy/creds.sock

EXPOSE 8080

CMD ["sh", "-c", \
  "mkdir -p /run/proxy && \
   mitmdump \
     --listen-port 8080 \
     --scripts /proxy/elhaz_resign.py \
     --set confdir=/run/mitmproxy"]
