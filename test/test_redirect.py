"""Tests for isSafeRedirect."""

import pytest

DOMAIN = "example.com"


@pytest.fixture(scope="module")
def fn(bin_mod):
    return bin_mod.isSafeRedirect


# ---------------------------------------------------------------------------
# Relative URLs — always safe

@pytest.mark.parametrize("url", [
    "/",
    "/dashboard",
    "/auth/login",
    "/path/to/resource?query=1",
    "/path#anchor",
])
def test_relative_urls_are_safe(fn, url):
    assert fn(url, DOMAIN) is True


# ---------------------------------------------------------------------------
# Same-domain absolute URLs — safe

@pytest.mark.parametrize("url", [
    "https://example.com/",
    "https://example.com/dashboard",
    "http://example.com/path",
    "https://sub.example.com/page",
    "https://deep.sub.example.com/",
])
def test_same_domain_absolute_urls_are_safe(fn, url):
    assert fn(url, DOMAIN) is True


# ---------------------------------------------------------------------------
# Different domain — blocked

@pytest.mark.parametrize("url", [
    "https://evil.com/",
    "https://evil.com/example.com",
    "https://notexample.com/",
    "http://attacker.io/steal",
    "https://example.com.evil.io/",
    "https://exampleXcom/",
])
def test_different_domain_urls_are_blocked(fn, url):
    assert fn(url, DOMAIN) is False


# ---------------------------------------------------------------------------
# Dangerous schemes — blocked

@pytest.mark.parametrize("url", [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "ftp://example.com/file",
    "file:///etc/passwd",
    "vbscript:msgbox(1)",
])
def test_dangerous_schemes_are_blocked(fn, url):
    assert fn(url, DOMAIN) is False


# ---------------------------------------------------------------------------
# Protocol-relative URLs — blocked

@pytest.mark.parametrize("url", [
    "//evil.com/steal",
    "//example.com/legit",
])
def test_protocol_relative_urls_are_blocked(fn, url):
    assert fn(url, DOMAIN) is False


# ---------------------------------------------------------------------------
# Empty / None — blocked

def test_empty_string_is_blocked(fn):
    assert fn("", DOMAIN) is False


def test_none_is_blocked(fn):
    assert fn(None, DOMAIN) is False


# ---------------------------------------------------------------------------
# Domain boundary edge cases

def test_subdomain_of_configured_domain_is_safe(fn):
    assert fn("https://api.example.com/v1", DOMAIN) is True


def test_domain_as_path_segment_is_blocked(fn):
    assert fn("https://evil.com/example.com/path", DOMAIN) is False


def test_url_with_port_same_domain_is_safe(fn):
    assert fn("https://example.com:8443/path", DOMAIN) is True


def test_url_with_port_different_domain_is_blocked(fn):
    assert fn("https://evil.com:443/path", DOMAIN) is False
