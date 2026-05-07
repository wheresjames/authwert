"""Tests for readPrivateKey, readCert, and readSiteCert."""

import os
import pytest
import authwert


# ---------------------------------------------------------------------------
# readPrivateKey

def test_readPrivateKey_valid_file(rsa_keypair):
    opts = {}
    result = authwert.readPrivateKey(rsa_keypair["prv_file"], opts)
    assert result is True
    assert "prvpem" in opts
    assert opts["prvpem"].startswith("-----BEGIN RSA PRIVATE KEY-----") or \
           opts["prvpem"].startswith("-----BEGIN PRIVATE KEY-----")


def test_readPrivateKey_derives_public_key(rsa_keypair):
    opts = {}
    authwert.readPrivateKey(rsa_keypair["prv_file"], opts)
    assert "pubpem" in opts
    assert opts["pubpem"].startswith("-----BEGIN PUBLIC KEY-----")


def test_readPrivateKey_derived_public_key_matches(rsa_keypair):
    opts = {}
    authwert.readPrivateKey(rsa_keypair["prv_file"], opts)
    assert opts["pubpem"] == rsa_keypair["pubpem"]


def test_readPrivateKey_nonexistent_file_returns_false():
    opts = {}
    result = authwert.readPrivateKey("/does/not/exist.pem", opts)
    assert result is False
    assert "prvpem" not in opts
    assert "pubpem" not in opts


def test_readPrivateKey_populates_opts_prvpem(rsa_keypair):
    opts = {"other": "value"}
    authwert.readPrivateKey(rsa_keypair["prv_file"], opts)
    assert "other" in opts
    assert "prvpem" in opts


# ---------------------------------------------------------------------------
# readCert

def test_readCert_valid_file(self_signed_cert):
    opts = {}
    result = authwert.readCert(self_signed_cert["file"], opts)
    assert result is True


def test_readCert_extracts_public_key(self_signed_cert):
    opts = {}
    authwert.readCert(self_signed_cert["file"], opts)
    assert "pubpem" in opts
    assert opts["pubpem"].startswith("-----BEGIN PUBLIC KEY-----")


def test_readCert_public_key_matches_keypair(self_signed_cert, rsa_keypair):
    """The cert was signed with the rsa_keypair private key — public keys should match."""
    opts = {}
    authwert.readCert(self_signed_cert["file"], opts)
    assert opts["pubpem"] == rsa_keypair["pubpem"]


def test_readCert_empty_file_returns_false(tmp_path):
    f = tmp_path / "empty.crt"
    f.write_text("")
    opts = {}
    result = authwert.readCert(str(f), opts)
    assert result is False


def test_readCert_invalid_content_raises(tmp_path):
    f = tmp_path / "bad.crt"
    f.write_text("not a certificate")
    opts = {}
    with pytest.raises(Exception):
        authwert.readCert(str(f), opts)


# ---------------------------------------------------------------------------
# libPath

def test_libPath_no_arg_returns_package_dir():
    p = authwert.libPath(None)
    assert os.path.isdir(p)
    assert os.path.basename(p) == "authwert"


def test_libPath_resolves_relative_to_package():
    p = authwert.libPath("web/login.html")
    assert os.path.isfile(p)


def test_libPath_project_txt_exists():
    assert os.path.isfile(authwert.libPath("PROJECT.txt"))
