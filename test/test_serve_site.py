"""Tests for the serveSite file-serving handler."""

import os
import time
import types
import pytest
import propertybag as pb
from conftest import make_ctx

COOKIE_ID = "auth_token"
SESSION_ID = "test-session-id"
ROOTPATH = "http://localhost:18401/auth"


# ---------------------------------------------------------------------------
# Helpers

def _make_serve_opts(serve_dir, authenticated=True):
    _p = pb.Bag({"verbose": False})
    _p.serve = serve_dir
    _p.cookieid = COOKIE_ID
    _p.rootpath = ROOTPATH
    _p.sessions = {}
    if authenticated:
        _p.sessions[SESSION_ID] = {
            "username": "testuser",
            "exp": time.time() + 3600,
            "sid": SESSION_ID,
        }
    return _p


def _make_req(path, authenticated=True):
    cookies = {COOKIE_ID: SESSION_ID} if authenticated else {}
    req = types.SimpleNamespace(path=path, cookies=cookies)
    return req


def _ctx(path, serve_dir, authenticated=True):
    req = _make_req(path, authenticated=authenticated)
    _p = _make_serve_opts(serve_dir, authenticated=authenticated)
    return make_ctx(req, _p)


# ---------------------------------------------------------------------------
# File serving

class TestServeSiteFileServing:

    async def test_serves_existing_file(self, bin_mod, tmp_path):
        f = tmp_path / "hello.txt"
        f.write_text("hello")
        ctx = _ctx("/hello.txt", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 200

    async def test_returns_404_for_missing_file(self, bin_mod, tmp_path):
        ctx = _ctx("/missing.txt", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 404

    async def test_serves_html_file(self, bin_mod, tmp_path):
        f = tmp_path / "index.html"
        f.write_text("<html></html>")
        ctx = _ctx("/index.html", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 200

    async def test_serves_nested_file(self, bin_mod, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        f = sub / "page.html"
        f.write_text("<html></html>")
        ctx = _ctx("/sub/page.html", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 200

    async def test_directory_with_index_redirects(self, bin_mod, tmp_path):
        sub = tmp_path / "app"
        sub.mkdir()
        (sub / "index.html").write_text("<html></html>")
        ctx = _ctx("/app", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 303
        assert "index.html" in resp.location

    async def test_directory_without_index_returns_404(self, bin_mod, tmp_path):
        sub = tmp_path / "empty_dir"
        sub.mkdir()
        ctx = _ctx("/empty_dir", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 404


# ---------------------------------------------------------------------------
# MIME type detection

class TestServeSiteMime:

    async def test_html_mime_type(self, bin_mod, tmp_path):
        (tmp_path / "page.html").write_text("<html></html>")
        ctx = _ctx("/page.html", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert "text/html" in resp.headers.get("Content-Type", "")

    async def test_js_mime_type(self, bin_mod, tmp_path):
        (tmp_path / "app.js").write_text("var x = 1;")
        ctx = _ctx("/app.js", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert "javascript" in resp.headers.get("Content-Type", "")

    async def test_css_mime_type(self, bin_mod, tmp_path):
        (tmp_path / "style.css").write_text("body{}")
        ctx = _ctx("/style.css", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert "css" in resp.headers.get("Content-Type", "")

    async def test_unknown_extension_defaults_to_text_plain(self, bin_mod, tmp_path):
        (tmp_path / "data.zzunknownext").write_text("raw data")
        ctx = _ctx("/data.zzunknownext", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert "text/plain" in resp.headers.get("Content-Type", "")


# ---------------------------------------------------------------------------
# Path traversal prevention

class TestServeSiteTraversal:

    async def test_dotdot_in_path_returns_403(self, bin_mod, tmp_path):
        parent = tmp_path.parent
        (parent / "secret.txt").write_text("secret")
        ctx = _ctx("/../secret.txt", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 403

    async def test_encoded_dotdot_cannot_escape(self, bin_mod, tmp_path):
        (tmp_path.parent / "secret.txt").write_text("top-secret")
        ctx = _ctx("/subdir/../../secret.txt", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status in (403, 404)

    async def test_etc_passwd_traversal_blocked(self, bin_mod, tmp_path):
        ctx = _ctx("/../../etc/passwd", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 403

    async def test_deeply_nested_file_is_allowed(self, bin_mod, tmp_path):
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "file.txt").write_text("ok")
        ctx = _ctx("/a/b/c/file.txt", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 200

    async def test_file_directly_in_serve_root_is_allowed(self, bin_mod, tmp_path):
        (tmp_path / "root.txt").write_text("ok")
        ctx = _ctx("/root.txt", str(tmp_path))
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 200


# ---------------------------------------------------------------------------
# Authentication

class TestServeSiteAuth:

    async def test_unauthenticated_request_redirects_to_login(self, bin_mod, tmp_path):
        (tmp_path / "index.html").write_text("<html></html>")
        ctx = _ctx("/index.html", str(tmp_path), authenticated=False)
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 303
        assert "/login" in resp.location

    async def test_unauthenticated_redirect_includes_rd(self, bin_mod, tmp_path):
        ctx = _ctx("/secret.html", str(tmp_path), authenticated=False)
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 303
        assert "rd=" in resp.location

    async def test_authenticated_request_serves_file(self, bin_mod, tmp_path):
        (tmp_path / "page.html").write_text("<html></html>")
        ctx = _ctx("/page.html", str(tmp_path), authenticated=True)
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 200

    async def test_expired_session_redirects_to_login(self, bin_mod, tmp_path):
        (tmp_path / "page.html").write_text("<html></html>")
        req = _make_req("/page.html", authenticated=True)
        _p = _make_serve_opts(str(tmp_path), authenticated=True)
        # Expire the session
        _p.sessions[SESSION_ID]["exp"] = time.time() - 1
        from conftest import make_ctx
        ctx = make_ctx(req, _p)
        resp = await bin_mod.serveSite(ctx, pb.Bag({}))
        assert resp.status == 303
        assert "/login" in resp.location
