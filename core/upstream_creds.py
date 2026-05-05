"""boto3-based upstream credential source for the native (non-Docker) path."""

__all__ = ["BotoCredentialSource"]

import os

import boto3
from botocore.credentials import Credentials


class BotoCredentialSource:
    """Fetches real AWS credentials via boto3's default credential chain.

    Holds a single boto3.Session for the lifetime of the proxy so that
    botocore's RefreshableCredentials machinery can refresh expiring credentials
    (SSO, instance profiles, assumed roles) without re-running provider
    discovery from scratch on every request.
    """

    def __init__(self) -> None:
        self._session = boto3.Session()

    def get(self) -> Credentials:
        raw = self._session.get_credentials()
        if raw is None:
            profile = os.environ.get("AWS_PROFILE", "<none>")
            raise RuntimeError(
                f"boto3 found no credentials (AWS_PROFILE={profile}). "
                "Start the proxy with a real profile: "
                "AWS_PROFILE=your-profile iam-agent-proxy"
            )
        creds = raw.get_frozen_credentials()
        return Credentials(creds.access_key, creds.secret_key, creds.token)
