"""
mitmproxy entry point — loads the elhaz-resign addon from the proxy package.

Usage:
    mitmdump --listen-port 8080 --scripts elhaz_resign.py

Config (env vars):
    ELHAZ_CONFIG_NAME   elhaz config name (default: sandbox-elhaz)
    ELHAZ_SOCKET_PATH   elhaz daemon socket path; set to /tmp/elhaz.sock in Docker
    PROXY_SOCK_PATH     Unix socket path for credential vending
                        (default: /run/proxy/creds.sock)
    PROXY_KEYPAIR_TTL   Keypair lifetime in seconds (default: 3600)
"""

from proxy.addon import addons, load  # noqa: F401
