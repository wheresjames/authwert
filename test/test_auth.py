"""Tests for authVerify and authLogin request handlers."""

import time
import jwt
import pytest
import propertybag as pb
import authwert
from conftest import (
    MockRequest,
    make_ctx,
    make_jwt_opts,
    make_session_opts,
)


def _make_jwt_token(prvpem, username="alice", exp_offset=3600, sid="sid1"):
    claims = {"username": username, "exp": int(time.time()) + exp_offset, "sid": sid}
    return jwt.encode(claims, prvpem, algorithm="RS256")


# ---------------------------------------------------------------------------
# authVerify

class TestAuthVerify:

    async def test_no_cookie_returns_401(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest(cookies={})
        ctx = make_ctx(req, _p)
        resp = await bin_mod.authVerify(ctx, pb.Bag({}))
        assert resp.status == 401

    async def test_valid_jwt_cookie_returns_200(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        token = _make_jwt_token(rsa_keypair["prvpem"])
        req = MockRequest(cookies={"auth_token": token})
        ctx = make_ctx(req, _p)
        resp = await bin_mod.authVerify(ctx, pb.Bag({}))
        assert resp.status == 200

    async def test_expired_jwt_returns_401(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        token = _make_jwt_token(rsa_keypair["prvpem"], exp_offset=-10)
        req = MockRequest(cookies={"auth_token": token})
        ctx = make_ctx(req, _p)
        resp = await bin_mod.authVerify(ctx, pb.Bag({}))
        assert resp.status == 401

    async def test_invalid_token_returns_401(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest(cookies={"auth_token": "garbage.token.value"})
        ctx = make_ctx(req, _p)
        resp = await bin_mod.authVerify(ctx, pb.Bag({}))
        assert resp.status == 401

    async def test_wrong_key_signature_returns_401(self, bin_mod, rsa_keypair, alt_rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        token = _make_jwt_token(alt_rsa_keypair["prvpem"])
        req = MockRequest(cookies={"auth_token": token})
        ctx = make_ctx(req, _p)
        resp = await bin_mod.authVerify(ctx, pb.Bag({}))
        assert resp.status == 401

    async def test_valid_session_cookie_returns_200(self, bin_mod):
        _p = make_session_opts()
        sid = "validtoken"
        _p.sessions[sid] = {"username": "alice", "exp": time.time() + 3600, "sid": sid}
        req = MockRequest(cookies={"auth_token": sid})
        ctx = make_ctx(req, _p)
        resp = await bin_mod.authVerify(ctx, pb.Bag({}))
        assert resp.status == 200

    async def test_expired_session_returns_401(self, bin_mod):
        _p = make_session_opts()
        sid = "expiredtoken"
        _p.sessions[sid] = {"username": "alice", "exp": time.time() - 1, "sid": sid}
        req = MockRequest(cookies={"auth_token": sid})
        ctx = make_ctx(req, _p)
        resp = await bin_mod.authVerify(ctx, pb.Bag({}))
        assert resp.status == 401

    async def test_unknown_session_returns_401(self, bin_mod):
        _p = make_session_opts()
        req = MockRequest(cookies={"auth_token": "unknown"})
        ctx = make_ctx(req, _p)
        resp = await bin_mod.authVerify(ctx, pb.Bag({}))
        assert resp.status == 401

    async def test_response_text_on_success(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        token = _make_jwt_token(rsa_keypair["prvpem"])
        req = MockRequest(cookies={"auth_token": token})
        ctx = make_ctx(req, _p)
        resp = await bin_mod.authVerify(ctx, pb.Bag({}))
        assert resp.text == "ok"

    async def test_response_text_on_failure(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest(cookies={})
        ctx = make_ctx(req, _p)
        resp = await bin_mod.authVerify(ctx, pb.Bag({}))
        assert "Denied" in resp.text or "denied" in resp.text.lower()


# ---------------------------------------------------------------------------
# authLogin — GET-style (no credentials, not logged in)

class TestAuthLoginUnauthenticated:

    async def test_get_returns_200_login_page(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 200

    async def test_get_with_rd_param_sets_default(self, bin_mod):
        _p = make_session_opts()
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 200
        assert q.rd  # should be populated with a default


# ---------------------------------------------------------------------------
# authLogin — POST with credentials

class TestAuthLoginCredentials:

    async def test_valid_credentials_jwt_redirects(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "alice", "password": "s3cr3t", "rd": "/dashboard"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 303
        assert "/dashboard" in resp.location

    async def test_valid_credentials_jwt_sets_cookie(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "alice", "password": "s3cr3t", "rd": "/"})
        resp = await bin_mod.authLogin(ctx, q)
        assert "auth_token" in resp.cookies
        cookie_val = resp.cookies["auth_token"].value
        assert len(cookie_val) > 0

    async def test_valid_credentials_jwt_cookie_is_valid_jwt(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "alice", "password": "s3cr3t", "rd": "/"})
        resp = await bin_mod.authLogin(ctx, q)
        cookie_val = resp.cookies["auth_token"].value
        decoded = jwt.decode(cookie_val, rsa_keypair["pubpem"], algorithms=["RS256"])
        assert decoded["username"] == "alice"

    async def test_valid_credentials_session_mode(self, bin_mod):
        _p = make_session_opts()
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "alice", "password": "s3cr3t", "rd": "/"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 303
        cookie_val = resp.cookies["auth_token"].value
        assert cookie_val in _p.sessions

    async def test_valid_credentials_session_stores_username(self, bin_mod):
        _p = make_session_opts()
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "alice", "password": "s3cr3t", "rd": "/"})
        await bin_mod.authLogin(ctx, q)
        session = next(iter(_p.sessions.values()))
        assert session["username"] == "alice"

    async def test_wrong_password_returns_403(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "alice", "password": "wrong", "rd": "/"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 403

    async def test_unknown_user_returns_403(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "nobody", "password": "s3cr3t", "rd": "/"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 403

    async def test_wildcard_user_matches_any_username(self, bin_mod):
        _p = make_session_opts()
        _p.userinf = {"*": {"password": "wildcard"}}
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "anyuser", "password": "wildcard", "rd": "/"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 303

    async def test_wildcard_user_wrong_password_blocked(self, bin_mod):
        _p = make_session_opts()
        _p.userinf = {"*": {"password": "wildcard"}}
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "anyuser", "password": "bad", "rd": "/"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 403

    async def test_exact_user_takes_priority_over_wildcard(self, bin_mod):
        _p = make_session_opts()
        _p.userinf = {
            "alice": {"password": "alicepw"},
            "*": {"password": "wildcard"},
        }
        req = MockRequest()
        ctx = make_ctx(req, _p)
        # alice's own password works
        q = pb.Bag({"username": "alice", "password": "alicepw", "rd": "/"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 303

    async def test_post_body_credentials_are_merged(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest(body_exists=True, post_data={"username": "alice", "password": "s3cr3t"})
        ctx = make_ctx(req, _p)
        q = pb.Bag({"rd": "/"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 303


# ---------------------------------------------------------------------------
# authLogin — already logged in

class TestAuthLoginAlreadyLoggedIn:

    async def test_logged_in_user_sees_logout_page(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        token = _make_jwt_token(rsa_keypair["prvpem"])
        req = MockRequest(cookies={"auth_token": token})
        ctx = make_ctx(req, _p)
        q = pb.Bag({})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 200


# ---------------------------------------------------------------------------
# authLogin — logout

class TestAuthLoginLogout:

    async def test_logout_clears_session_cookie(self, bin_mod):
        _p = make_session_opts()
        sid = "activesid"
        _p.sessions[sid] = {"username": "alice", "exp": time.time() + 3600, "sid": sid}
        req = MockRequest(cookies={"auth_token": sid})
        ctx = make_ctx(req, _p)
        q = pb.Bag({"logout": "1", "rd": "/"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 200
        assert resp.cookies["auth_token"].value == ""

    async def test_logout_removes_session_from_store(self, bin_mod):
        _p = make_session_opts()
        sid = "to_be_removed"
        _p.sessions[sid] = {"username": "alice", "exp": time.time() + 3600, "sid": sid}
        req = MockRequest(cookies={"auth_token": sid})
        ctx = make_ctx(req, _p)
        q = pb.Bag({"logout": "1", "rd": "/"})
        await bin_mod.authLogin(ctx, q)
        assert sid not in _p.sessions

    async def test_logout_when_not_logged_in_returns_login_page(self, bin_mod):
        _p = make_session_opts()
        req = MockRequest(cookies={})
        ctx = make_ctx(req, _p)
        q = pb.Bag({"logout": "1", "rd": "/"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 200


# ---------------------------------------------------------------------------
# authLogin — open redirect protection

class TestAuthLoginRedirectSafety:

    async def test_safe_relative_redirect_is_followed(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "alice", "password": "s3cr3t", "rd": "/safe"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 303
        assert resp.location == "/safe"

    async def test_open_redirect_to_external_domain_blocked(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "alice", "password": "s3cr3t", "rd": "https://evil.com/steal"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 303
        assert "evil.com" not in resp.location

    async def test_open_redirect_javascript_scheme_blocked(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "alice", "password": "s3cr3t", "rd": "javascript:alert(1)"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 303
        assert "javascript" not in resp.location

    async def test_same_domain_redirect_allowed(self, bin_mod, rsa_keypair):
        _p = make_jwt_opts(rsa_keypair)
        req = MockRequest()
        ctx = make_ctx(req, _p)
        q = pb.Bag({"username": "alice", "password": "s3cr3t",
                    "rd": "https://example.com/app"})
        resp = await bin_mod.authLogin(ctx, q)
        assert resp.status == 303
        assert resp.location == "https://example.com/app"
