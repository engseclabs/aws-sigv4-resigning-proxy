"""boto3-based upstream credential source for the native (non-Docker) path."""

__all__ = ["BotoCredentialSource"]

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
        creds = self._session.get_credentials().get_frozen_credentials()
        return Credentials(creds.access_key, creds.secret_key, creds.token)
