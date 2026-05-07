"""Tests for createSessionToken and getSessionInfo."""

import time
import jwt
import pytest
import authwert


# ---------------------------------------------------------------------------
# createSessionToken

def test_createSessionToken_returns_string(rsa_keypair):
    claims = {"username": "alice", "exp": int(time.time()) + 3600}
    opts = {"prvpem": rsa_keypair["prvpem"], "algorithm": "RS256"}
    token = authwert.createSessionToken(claims, opts)
    assert isinstance(token, str)
    assert len(token) > 0


def test_createSessionToken_encodes_claims(rsa_keypair):
    exp = int(time.time()) + 3600
    claims = {"username": "alice", "exp": exp, "sid": "abc123"}
    opts = {"prvpem": rsa_keypair["prvpem"], "algorithm": "RS256"}
    token = authwert.createSessionToken(claims, opts)
    decoded = jwt.decode(token, rsa_keypair["pubpem"], algorithms=["RS256"])
    assert decoded["username"] == "alice"
    assert decoded["sid"] == "abc123"
    assert decoded["exp"] == exp


def test_createSessionToken_without_prvpem_returns_none():
    opts = {}
    token = authwert.createSessionToken({"username": "alice"}, opts)
    assert token is None


def test_createSessionToken_sets_default_algorithm(rsa_keypair):
    opts = {"prvpem": rsa_keypair["prvpem"]}
    claims = {"username": "alice", "exp": int(time.time()) + 3600}
    token = authwert.createSessionToken(claims, opts)
    assert opts["algorithm"] == "RS256"
    decoded = jwt.decode(token, rsa_keypair["pubpem"], algorithms=["RS256"])
    assert decoded["username"] == "alice"


def test_createSessionToken_respects_explicit_algorithm(rsa_keypair):
    opts = {"prvpem": rsa_keypair["prvpem"], "algorithm": "RS256"}
    claims = {"username": "bob", "exp": int(time.time()) + 3600}
    token = authwert.createSessionToken(claims, opts)
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"


# ---------------------------------------------------------------------------
# getSessionInfo — JWT path

def test_getSessionInfo_valid_jwt(rsa_keypair):
    exp = int(time.time()) + 3600
    claims = {"username": "alice", "exp": exp, "sid": "s1"}
    opts = {"prvpem": rsa_keypair["prvpem"], "pubpem": rsa_keypair["pubpem"], "algorithm": "RS256"}
    token = authwert.createSessionToken(claims, opts)
    result = authwert.getSessionInfo(token, opts)
    assert result is not None
    assert result["username"] == "alice"
    assert result["sid"] == "s1"


def test_getSessionInfo_expired_jwt_returns_none(rsa_keypair):
    claims = {"username": "alice", "exp": int(time.time()) - 10, "sid": "s2"}
    token = jwt.encode(claims, rsa_keypair["prvpem"], algorithm="RS256")
    opts = {"pubpem": rsa_keypair["pubpem"], "algorithm": "RS256"}
    assert authwert.getSessionInfo(token, opts) is None


def test_getSessionInfo_invalid_signature_returns_none(rsa_keypair, alt_rsa_keypair):
    claims = {"username": "alice", "exp": int(time.time()) + 3600}
    token = jwt.encode(claims, alt_rsa_keypair["prvpem"], algorithm="RS256")
    opts = {"pubpem": rsa_keypair["pubpem"], "algorithm": "RS256"}
    assert authwert.getSessionInfo(token, opts) is None


def test_getSessionInfo_malformed_token_returns_none(rsa_keypair):
    opts = {"pubpem": rsa_keypair["pubpem"], "algorithm": "RS256"}
    assert authwert.getSessionInfo("not.a.jwt", opts) is None


def test_getSessionInfo_empty_token_returns_none(rsa_keypair):
    opts = {"pubpem": rsa_keypair["pubpem"], "algorithm": "RS256"}
    assert authwert.getSessionInfo("", opts) is None


def test_getSessionInfo_sets_default_algorithm_on_opts(rsa_keypair):
    exp = int(time.time()) + 3600
    claims = {"username": "alice", "exp": exp}
    token = jwt.encode(claims, rsa_keypair["prvpem"], algorithm="RS256")
    opts = {"pubpem": rsa_keypair["pubpem"]}
    authwert.getSessionInfo(token, opts)
    assert opts["algorithm"] == "RS256"


# ---------------------------------------------------------------------------
# getSessionInfo — session-id path

def _session_opts(sessions):
    return {"sessions": sessions}


def test_getSessionInfo_valid_session():
    sid = "tok123"
    exp = time.time() + 3600
    sessions = {sid: {"username": "alice", "exp": exp, "sid": sid}}
    result = authwert.getSessionInfo(sid, _session_opts(sessions))
    assert result is not None
    assert result["username"] == "alice"


def test_getSessionInfo_expired_session_returns_none():
    sid = "tok_exp"
    sessions = {sid: {"username": "alice", "exp": time.time() - 1, "sid": sid}}
    assert authwert.getSessionInfo(sid, _session_opts(sessions)) is None


def test_getSessionInfo_unknown_session_token_returns_none():
    sessions = {"other": {"username": "alice", "exp": time.time() + 3600, "sid": "other"}}
    assert authwert.getSessionInfo("missing", _session_opts(sessions)) is None


def test_getSessionInfo_session_without_exp_returns_none():
    sid = "no_exp"
    sessions = {sid: {"username": "alice", "sid": sid}}
    assert authwert.getSessionInfo(sid, _session_opts(sessions)) is None


def test_getSessionInfo_no_pubpem_no_sessions_returns_none():
    assert authwert.getSessionInfo("anything", {}) is None


def test_getSessionInfo_jwt_takes_priority_over_sessions(rsa_keypair):
    exp = int(time.time()) + 3600
    claims = {"username": "jwt_user", "exp": exp}
    token = jwt.encode(claims, rsa_keypair["prvpem"], algorithm="RS256")
    opts = {
        "pubpem": rsa_keypair["pubpem"],
        "algorithm": "RS256",
        "sessions": {token: {"username": "session_user", "exp": exp, "sid": token}},
    }
    result = authwert.getSessionInfo(token, opts)
    assert result["username"] == "jwt_user"
