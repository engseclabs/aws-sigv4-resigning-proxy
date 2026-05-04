"""Tests for proxy/exceptions.py — hierarchy and error_status mapping."""

import pytest

from core.exceptions import ProxyError, UpstreamError, ValidationError, error_status


# --------------------------------------------------------------------------- #
# Hierarchy
# --------------------------------------------------------------------------- #

def test_validation_error_is_proxy_error():
    assert issubclass(ValidationError, ProxyError)


def test_upstream_error_is_proxy_error():
    assert issubclass(UpstreamError, ProxyError)


def test_proxy_error_default_code():
    exc = ProxyError("oops")
    assert exc.code == "InternalError"
    assert str(exc) == "oops"


def test_proxy_error_custom_code():
    exc = ProxyError("oops", code="CustomCode")
    assert exc.code == "CustomCode"


def test_validation_error_code():
    exc = ValidationError("bad token")
    assert exc.code == "InvalidClientTokenId"


def test_upstream_error_code():
    exc = UpstreamError("service down")
    assert exc.code == "ServiceUnavailable"


# --------------------------------------------------------------------------- #
# error_status
# --------------------------------------------------------------------------- #

def test_error_status_validation_error():
    assert error_status(ValidationError("x")) == 403


def test_error_status_upstream_error():
    assert error_status(UpstreamError("x")) == 503


def test_error_status_base_proxy_error_returns_500():
    assert error_status(ProxyError("x")) == 500


def test_error_status_unknown_subclass_returns_500():
    class _Custom(ProxyError):
        pass

    assert error_status(_Custom("x")) == 500
