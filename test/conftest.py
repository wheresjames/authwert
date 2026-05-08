import os
import sys
import time
import types
import datetime
import importlib.util

import pytest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import propertybag as pb

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import authwert


# ---------------------------------------------------------------------------
# Module import

@pytest.fixture(scope="session")
def bin_mod():
    """Import bin/authwert as a module without executing main()."""
    from importlib.machinery import SourceFileLoader
    path = os.path.join(PROJECT_ROOT, "bin", "authwert")
    loader = SourceFileLoader("authwert_bin", path)
    spec = importlib.util.spec_from_loader("authwert_bin", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Crypto fixtures

@pytest.fixture(scope="session")
def rsa_keypair(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("keys")
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    prv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    prv_file = tmp / "test.pem"
    prv_file.write_text(prv_pem)
    return {"prvpem": prv_pem, "pubpem": pub_pem, "prv_file": str(prv_file), "key": key}


@pytest.fixture(scope="session")
def alt_rsa_keypair():
    """A second, unrelated key pair for signature-mismatch tests."""
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    return {
        "prvpem": key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
        "pubpem": key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
    }


@pytest.fixture(scope="session")
def self_signed_cert(rsa_keypair, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("certs")
    key = rsa_keypair["key"]
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256(), default_backend())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    cert_file = tmp / "test.crt"
    cert_file.write_text(pem)
    return {"pem": pem, "file": str(cert_file)}


# ---------------------------------------------------------------------------
# Options / context helpers

def make_jwt_opts(rsa_keypair):
    _p = pb.Bag({
        "cookieid": "auth_token",
        "domain": "example.com",
        "exptime": 3600,
        "verbose": False,
        "rootpath": "/auth",
        "algorithm": "RS256",
    })
    _p.prvpem = rsa_keypair["prvpem"]
    _p.pubpem = rsa_keypair["pubpem"]
    _p.sessions = {}
    _p.userinf = {"alice": {"password": "s3cr3t"}, "*": {"password": "wildcard"}}
    _p.dbauth = None
    return _p


def make_session_opts():
    # Do NOT set prvpem/pubpem — their presence in the Bag triggers the JWT path
    _p = pb.Bag({
        "cookieid": "auth_token",
        "domain": "example.com",
        "exptime": 3600,
        "verbose": False,
        "rootpath": "/auth",
    })
    _p.sessions = {}
    _p.userinf = {"alice": {"password": "s3cr3t"}, "*": {"password": "wildcard"}}
    _p.dbauth = None
    return _p


class MockRequest:
    def __init__(self, cookies=None, path="/", body_exists=False, post_data=None, headers=None):
        self.cookies = cookies or {}
        self.path = path
        self.body_exists = body_exists
        self._post_data = post_data or {}
        self.headers = headers or {}

    async def post(self):
        return dict(self._post_data)


def make_ctx(req, _p):
    opts = types.SimpleNamespace(_p=_p)
    return types.SimpleNamespace(req=req, opts=opts)
