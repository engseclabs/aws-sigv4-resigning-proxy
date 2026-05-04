"""boto3-based upstream credential source for the native (non-Docker) path."""

__all__ = ["BotoCredentialSource"]

import boto3
from botocore.credentials import Credentials


class BotoCredentialSource:
    """Fetches real AWS credentials via the standard boto3 credential provider chain.

    Botocore's provider chain handles caching and refresh internally, so no
    explicit cache layer is needed here.
    """

    def get(self) -> Credentials:
        session = boto3.Session()
        creds = session.get_credentials().get_frozen_credentials()
        return Credentials(creds.access_key, creds.secret_key, creds.token)
