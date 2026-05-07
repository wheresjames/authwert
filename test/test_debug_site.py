"""Tests for the debugSite file-serving handler."""

import os
import types
import pytest
import propertybag as pb
from conftest import make_ctx


# ---------------------------------------------------------------------------
# Helpers

def _make_debug_opts(debug_dir):
    _p = pb.Bag({"verbose": False})
    _p.debug = debug_dir
    return _p


def _make_req(path):
    req = types.SimpleNamespace(path=path)
    return req


def _ctx(path, debug_dir):
    req = _make_req(path)
    _p = _make_debug_opts(debug_dir)
    return make_ctx(req, _p)


# ---------------------------------------------------------------------------
# File serving

class TestDebugSiteFileServing:

    async def test_serves_existing_file(self, bin_mod, tmp_path):
        f = tmp_path / "hello.txt"
        f.write_text("hello")
        ctx = _ctx("/debug/hello.txt", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert resp.status == 200

    async def test_returns_404_for_missing_file(self, bin_mod, tmp_path):
        ctx = _ctx("/debug/missing.txt", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert resp.status == 404

    async def test_serves_html_file(self, bin_mod, tmp_path):
        f = tmp_path / "index.html"
        f.write_text("<html></html>")
        ctx = _ctx("/debug/index.html", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert resp.status == 200

    async def test_serves_nested_file(self, bin_mod, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        f = sub / "page.html"
        f.write_text("<html></html>")
        ctx = _ctx("/debug/sub/page.html", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert resp.status == 200

    async def test_directory_with_index_redirects(self, bin_mod, tmp_path):
        sub = tmp_path / "app"
        sub.mkdir()
        (sub / "index.html").write_text("<html></html>")
        ctx = _ctx("/debug/app", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert resp.status == 303
        assert "index.html" in resp.location

    async def test_directory_without_index_returns_404(self, bin_mod, tmp_path):
        sub = tmp_path / "empty_dir"
        sub.mkdir()
        ctx = _ctx("/debug/empty_dir", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert resp.status == 404


# ---------------------------------------------------------------------------
# MIME type detection

class TestDebugSiteMime:

    async def test_html_mime_type(self, bin_mod, tmp_path):
        (tmp_path / "page.html").write_text("<html></html>")
        ctx = _ctx("/debug/page.html", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert "text/html" in resp.headers.get("Content-Type", "")

    async def test_js_mime_type(self, bin_mod, tmp_path):
        (tmp_path / "app.js").write_text("var x = 1;")
        ctx = _ctx("/debug/app.js", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert "javascript" in resp.headers.get("Content-Type", "")

    async def test_css_mime_type(self, bin_mod, tmp_path):
        (tmp_path / "style.css").write_text("body{}")
        ctx = _ctx("/debug/style.css", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert "css" in resp.headers.get("Content-Type", "")

    async def test_unknown_extension_defaults_to_text_plain(self, bin_mod, tmp_path):
        (tmp_path / "data.zzunknownext").write_text("raw data")
        ctx = _ctx("/debug/data.zzunknownext", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert "text/plain" in resp.headers.get("Content-Type", "")


# ---------------------------------------------------------------------------
# Path traversal prevention

class TestDebugSiteTraversal:

    async def test_dotdot_in_path_returns_403(self, bin_mod, tmp_path):
        parent = tmp_path.parent
        (parent / "secret.txt").write_text("secret")
        ctx = _ctx("/debug/../secret.txt", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert resp.status == 403

    async def test_encoded_dotdot_cannot_escape(self, bin_mod, tmp_path):
        (tmp_path.parent / "secret.txt").write_text("top-secret")
        ctx = _ctx("/debug/subdir/../../secret.txt", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert resp.status in (403, 404)

    async def test_etc_passwd_traversal_blocked(self, bin_mod, tmp_path):
        ctx = _ctx("/debug/../../../etc/passwd", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert resp.status == 403

    async def test_deeply_nested_file_within_debug_is_allowed(self, bin_mod, tmp_path):
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "file.txt").write_text("ok")
        ctx = _ctx("/debug/a/b/c/file.txt", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert resp.status == 200

    async def test_file_directly_in_debug_root_is_allowed(self, bin_mod, tmp_path):
        (tmp_path / "root.txt").write_text("ok")
        ctx = _ctx("/debug/root.txt", str(tmp_path))
        resp = await bin_mod.debugSite(ctx, pb.Bag({}))
        assert resp.status == 200
