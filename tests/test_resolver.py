"""Tests for proxy/resolver.py — ActionResolver protocol dispatch and map.json lookup."""

import json
import re
import tempfile
from pathlib import Path

import pytest

from core.resolver import ActionResolver, _compile_uri_template


# --------------------------------------------------------------------------- #
# _compile_uri_template
# --------------------------------------------------------------------------- #

def test_compile_simple_path():
    rx, vars_, qs = _compile_uri_template("/{Bucket}")
    assert vars_ == ["Bucket"]
    assert qs == frozenset()
    assert rx.match("/my-bucket")
    assert not rx.match("/my-bucket/key")


def test_compile_greedy_key():
    rx, vars_, qs = _compile_uri_template("/{Bucket}/{Key+}")
    assert vars_ == ["Bucket", "Key"]
    assert rx.match("/bucket/path/to/key")
    assert not rx.match("/bucket")


def test_compile_bare_qs_key():
    rx, vars_, qs = _compile_uri_template("/{Bucket}/{Key+}?acl")
    assert qs == frozenset({"acl"})
    # path regex does not include the query part
    assert rx.match("/bucket/key")


def test_compile_multi_qs_key():
    rx, vars_, qs = _compile_uri_template("/{Bucket}?versioning&replication")
    assert qs == frozenset({"versioning", "replication"})


def test_compile_qs_keys_lowercased():
    _, _, qs = _compile_uri_template("/{Key+}?RenameObject")
    assert "renameobject" in qs


# --------------------------------------------------------------------------- #
# ActionResolver fixture
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def resolver():
    return ActionResolver()


# --------------------------------------------------------------------------- #
# json protocol (DynamoDB, KMS, etc.)
# --------------------------------------------------------------------------- #

def test_dynamodb_getitem(resolver):
    actions = resolver.resolve(
        "POST", "dynamodb.us-east-1.amazonaws.com", "/",
        {"x-amz-target": "DynamoDB_20120810.GetItem"}, b"{}", "dynamodb",
    )
    assert actions == ["dynamodb:GetItem"]


def test_dynamodb_putitem(resolver):
    actions = resolver.resolve(
        "POST", "dynamodb.us-east-1.amazonaws.com", "/",
        {"x-amz-target": "DynamoDB_20120810.PutItem"}, b"{}", "dynamodb",
    )
    assert actions == ["dynamodb:PutItem"]


def test_kms_decrypt(resolver):
    actions = resolver.resolve(
        "POST", "kms.us-east-1.amazonaws.com", "/",
        {"x-amz-target": "TrentService.Decrypt"}, b"{}", "kms",
    )
    assert actions == ["kms:Decrypt"]


def test_secretsmanager_get_secret(resolver):
    actions = resolver.resolve(
        "POST", "secretsmanager.us-east-1.amazonaws.com", "/",
        {"x-amz-target": "secretsmanager.GetSecretValue"}, b"{}", "secretsmanager",
    )
    assert actions == ["secretsmanager:GetSecretValue"]


# --------------------------------------------------------------------------- #
# query / ec2 protocol (IAM, STS, EC2, SQS)
# --------------------------------------------------------------------------- #

def test_iam_create_role(resolver):
    actions = resolver.resolve(
        "POST", "iam.amazonaws.com", "/",
        {}, b"Action=CreateRole&Version=2010-05-08", "iam",
    )
    assert actions == ["iam:CreateRole"]


def test_sts_assume_role(resolver):
    actions = resolver.resolve(
        "POST", "sts.amazonaws.com", "/",
        {}, b"Action=AssumeRole&Version=2011-06-15", "sts",
    )
    assert actions == ["sts:AssumeRole"]


def test_sts_get_caller_identity_permissionless(resolver):
    actions = resolver.resolve(
        "POST", "sts.amazonaws.com", "/",
        {}, b"Action=GetCallerIdentity&Version=2011-06-15", "sts",
    )
    assert actions == []


def test_ec2_describe_instances(resolver):
    actions = resolver.resolve(
        "POST", "ec2.us-east-1.amazonaws.com", "/",
        {}, b"Action=DescribeInstances&Version=2016-11-15", "ec2",
    )
    assert actions == ["ec2:DescribeInstances"]


# --------------------------------------------------------------------------- #
# rest-xml protocol (S3)
# --------------------------------------------------------------------------- #

def test_s3_get_object(resolver):
    assert resolver.resolve("GET", "s3.amazonaws.com", "/bucket/key", {}, b"", "s3") == ["s3:GetObject"]


def test_s3_get_object_acl(resolver):
    assert resolver.resolve("GET", "s3.amazonaws.com", "/bucket/key?acl", {}, b"", "s3") == ["s3:GetObjectAcl"]


def test_s3_get_object_tagging(resolver):
    assert resolver.resolve("GET", "s3.amazonaws.com", "/bucket/key?tagging", {}, b"", "s3") == ["s3:GetObjectTagging"]


def test_s3_put_object(resolver):
    assert resolver.resolve("PUT", "s3.amazonaws.com", "/bucket/key", {}, b"data", "s3") == ["s3:PutObject"]


def test_s3_copy_object(resolver):
    actions = resolver.resolve(
        "PUT", "s3.amazonaws.com", "/bucket/dest-key",
        {"x-amz-copy-source": "/src-bucket/src-key"}, b"", "s3",
    )
    # CopyObject requires multiple permissions on source and destination
    assert "s3:GetObject" in actions
    assert "s3:PutObject" in actions


def test_s3_upload_part(resolver):
    actions = resolver.resolve(
        "PUT", "s3.amazonaws.com", "/bucket/key?partNumber=1&uploadId=abc",
        {}, b"data", "s3",
    )
    assert actions == ["s3:PutObject"]


def test_s3_delete_object(resolver):
    assert resolver.resolve("DELETE", "s3.amazonaws.com", "/bucket/key", {}, b"", "s3") == ["s3:DeleteObject"]


def test_s3_list_objects(resolver):
    assert resolver.resolve("GET", "s3.amazonaws.com", "/bucket", {}, b"", "s3") == ["s3:ListBucket"]


# --------------------------------------------------------------------------- #
# rest-json protocol (Lambda)
# --------------------------------------------------------------------------- #

def test_lambda_invoke(resolver):
    actions = resolver.resolve(
        "POST", "lambda.us-east-1.amazonaws.com",
        "/2015-03-31/functions/my-function/invocations", {}, b"{}", "lambda",
    )
    assert actions == ["lambda:InvokeFunction"]


def test_lambda_list_functions(resolver):
    actions = resolver.resolve(
        "GET", "lambda.us-east-1.amazonaws.com",
        "/2015-03-31/functions", {}, b"", "lambda",
    )
    assert actions == ["lambda:ListFunctions"]


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #

def test_unknown_service_returns_empty(resolver):
    actions = resolver.resolve("POST", "notaservice.amazonaws.com", "/", {}, b"", "notaservice")
    assert actions == []


def test_unresolvable_operation_returns_empty(resolver):
    # Valid service but path matches nothing
    actions = resolver.resolve("GET", "lambda.amazonaws.com", "/no-such-path", {}, b"", "lambda")
    assert actions == []


def test_fallback_synthesis_for_unmapped_operation(resolver, tmp_path):
    # Build a minimal map.json with no entry for this service
    minimal_map = {
        "sdk_method_iam_mappings": {},
        "sdk_permissionless_actions": [],
        "sdk_service_mappings": {},
        "service_sdk_mappings": {"sts": ["STS"]},
    }
    p = tmp_path / "map.json"
    p.write_text(json.dumps(minimal_map))
    r = ActionResolver(p)
    # STS AssumeRole should fall back to synthesised "sts:AssumeRole"
    actions = r.resolve("POST", "sts.amazonaws.com", "/", {}, b"Action=AssumeRole", "sts")
    assert actions == ["sts:AssumeRole"]
