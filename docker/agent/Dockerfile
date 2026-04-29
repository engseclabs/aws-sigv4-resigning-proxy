FROM python:3.12-slim

RUN pip install --no-cache-dir awscli

WORKDIR /agent

COPY proxy-creds /usr/local/bin/proxy-creds
RUN chmod +x /usr/local/bin/proxy-creds

COPY test_resign.sh /agent/test_resign.sh
RUN chmod +x /agent/test_resign.sh

# AWS CLI config: use proxy-creds for the "proxy" profile.
# HTTPS_PROXY and AWS_CA_BUNDLE are injected by docker-compose.
RUN mkdir -p /root/.aws && printf '\
[profile proxy]\n\
credential_process = /usr/local/bin/proxy-creds\n\
region = us-east-1\n' > /root/.aws/config

ENV AWS_PROFILE=proxy
ENV PROXY_SOCK_PATH=/run/proxy/creds.sock

# Keep container running so `docker compose exec agent <cmd>` works.
CMD ["sleep", "infinity"]
