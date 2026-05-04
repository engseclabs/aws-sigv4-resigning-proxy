"""Tests for proxy/sigv4.py — parse_aws_host and validate_sigv4."""

import hashlib
import hmac

import pytest

from core.sigv4 import _parse_auth_header, _signing_key, parse_aws_host, validate_sigv4
from core.credentials import CredentialStore

from conftest import make_signed_request, make_store_with


# --------------------------------------------------------------------------- #
# parse_aws_host
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("host, expected", [
    ("s3.us-east-1.amazonaws.com",             ("s3",        "us-east-1")),
    ("ec2.us-west-2.amazonaws.com",            ("ec2",       "us-west-2")),
    ("sts.amazonaws.com",                      ("sts",       "us-east-1")),
    ("s3.amazonaws.com",                       ("s3",        "us-east-1")),
    ("mybucket.s3.amazonaws.com",              ("s3",        "us-east-1")),
    ("mybucket.s3.eu-west-1.amazonaws.com",    ("s3",        "eu-west-1")),
    ("lambda.amazonaws.com",                   ("lambda",    "us-east-1")),
])
def test_parse_aws_host_known_patterns(host, expected):
    assert parse_aws_host(host) == expected


@pytest.mark.parametrize("host", [
    "example.com",
    "google.com",
    "notaws.amazonaws.example.com",
])
def test_parse_aws_host_non_aws_returns_none(host):
    assert parse_aws_host(host) is None


def test_parse_aws_host_strips_port():
    assert parse_aws_host("s3.amazonaws.com:443") == ("s3", "us-east-1")


def test_parse_aws_host_case_insensitive():
    assert parse_aws_host("S3.US-EAST-1.AMAZONAWS.COM") == ("s3", "us-east-1")


# --------------------------------------------------------------------------- #
# _parse_auth_header
# --------------------------------------------------------------------------- #

def test_parse_auth_header_valid():
    auth = (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIATEST/20240101/us-east-1/s3/aws4_request,"
        "SignedHeaders=host;x-amz-date,"
        "Signature=abc123"
    )
    result = _parse_auth_header(auth)
    assert result is not None
    assert result["Credential"] == "AKIATEST/20240101/us-east-1/s3/aws4_request"
    assert result["SignedHeaders"] == "host;x-amz-date"
    assert result["Signature"] == "abc123"


def test_parse_auth_header_wrong_scheme_returns_none():
    assert _parse_auth_header("Bearer token123") is None


def test_parse_auth_header_missing_signature_returns_none():
    auth = (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIATEST/20240101/us-east-1/s3/aws4_request,"
        "SignedHeaders=host;x-amz-date"
    )
    assert _parse_auth_header(auth) is None


def test_parse_auth_header_empty_returns_none():
    assert _parse_auth_header("") is None


# --------------------------------------------------------------------------- #
# validate_sigv4 — happy path
# --------------------------------------------------------------------------- #

def test_validate_sigv4_valid_signature():
    store = make_store_with(access_key_id="AKIAPROXYTEST12345678", secret="testsecret")
    method, url, headers, body = make_signed_request(
        access_key_id="AKIAPROXYTEST12345678",
        secret="testsecret",
    )
    assert validate_sigv4(method, url, headers, body, store) is True


def test_validate_sigv4_accepts_prev_secret():
    store = make_store_with(
        access_key_id="AKIAPROXYTEST12345678",
        secret="newsecret",
        prev_secret="oldsecret",
    )
    method, url, headers, body = make_signed_request(
        access_key_id="AKIAPROXYTEST12345678",
        secret="oldsecret",
    )
    assert validate_sigv4(method, url, headers, body, store) is True


# --------------------------------------------------------------------------- #
# validate_sigv4 — rejection paths
# --------------------------------------------------------------------------- #

def test_validate_sigv4_missing_auth_header_returns_false():
    store = CredentialStore()
    assert validate_sigv4("GET", "https://s3.amazonaws.com/bucket/key", {}, b"", store) is False


def test_validate_sigv4_wrong_secret_returns_false():
    store = make_store_with(access_key_id="AKIAPROXYTEST12345678", secret="correct")
    method, url, headers, body = make_signed_request(
        access_key_id="AKIAPROXYTEST12345678",
        secret="wrong",
    )
    assert validate_sigv4(method, url, headers, body, store) is False


def test_validate_sigv4_unknown_key_returns_false():
    store = make_store_with(access_key_id="AKIAPROXYTEST12345678", secret="s")
    method, url, headers, body = make_signed_request(
        access_key_id="AKIADIFFERENTKEY12345",
        secret="s",
    )
    assert validate_sigv4(method, url, headers, body, store) is False


def test_validate_sigv4_malformed_credential_field_returns_false():
    store = CredentialStore()
    headers = {
        "authorization": "AWS4-HMAC-SHA256 Credential=BADCRED,SignedHeaders=host,Signature=abc",
        "x-amz-date": "20240101T000000Z",
    }
    assert validate_sigv4("GET", "https://s3.amazonaws.com/bucket/key", headers, b"", store) is False
