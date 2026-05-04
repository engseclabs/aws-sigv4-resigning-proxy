"""Tests for proxy/allowlist.py — Allowlist policy checking."""

import json
import pytest
from pathlib import Path

from core.allowlist import Allowlist


def _make(actions):
    """Build an Allowlist from a list of action strings."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
    }
    return Allowlist(policy)


# --------------------------------------------------------------------------- #
# Basic permit / deny
# --------------------------------------------------------------------------- #

def test_exact_action_permitted():
    al = _make(["s3:GetObject"])
    assert al.permits(["s3:GetObject"])


def test_exact_action_denied():
    al = _make(["s3:GetObject"])
    assert not al.permits(["s3:PutObject"])


def test_case_insensitive_match():
    al = _make(["S3:GetObject"])
    assert al.permits(["s3:getobject"])
    assert al.permits(["S3:GetObject"])


def test_empty_action_list_always_permitted():
    al = _make([])
    assert al.permits([])


def test_all_actions_must_be_permitted():
    al = _make(["s3:GetObject", "s3:PutObject"])
    assert al.permits(["s3:GetObject", "s3:PutObject"])
    assert not al.permits(["s3:GetObject", "s3:DeleteObject"])


# --------------------------------------------------------------------------- #
# Wildcard matching
# --------------------------------------------------------------------------- #

def test_service_wildcard():
    al = _make(["s3:*"])
    assert al.permits(["s3:GetObject"])
    assert al.permits(["s3:PutObject"])
    assert not al.permits(["ec2:DescribeInstances"])


def test_global_wildcard():
    al = _make(["*"])
    assert al.permits(["s3:GetObject"])
    assert al.permits(["iam:CreateRole"])
    assert al.permits(["anything:whatever"])


def test_action_string_not_list():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    al = Allowlist(policy)
    assert al.permits(["s3:GetObject"])


# --------------------------------------------------------------------------- #
# Deny statements are ignored
# --------------------------------------------------------------------------- #

def test_deny_statements_ignored():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
            {"Effect": "Deny",  "Action": ["s3:GetObject"], "Resource": "*"},
        ],
    }
    al = Allowlist(policy)
    # Deny is not evaluated; only Allow statements matter
    assert al.permits(["s3:GetObject"])


# --------------------------------------------------------------------------- #
# from_file
# --------------------------------------------------------------------------- #

def test_from_file(tmp_path):
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": "*"}],
    }
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(policy))
    al = Allowlist.from_file(p)
    assert al.permits(["kms:Decrypt"])
    assert not al.permits(["kms:GenerateDataKey"])


# --------------------------------------------------------------------------- #
# Multiple statements
# --------------------------------------------------------------------------- #

def test_multiple_statements_unioned():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["kms:Decrypt"],  "Resource": "*"},
        ],
    }
    al = Allowlist(policy)
    assert al.permits(["s3:GetObject"])
    assert al.permits(["kms:Decrypt"])
    assert al.permits(["s3:GetObject", "kms:Decrypt"])
    assert not al.permits(["s3:PutObject"])
