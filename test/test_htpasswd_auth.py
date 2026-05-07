"""Tests for authwert/etc/auth-htpasswd.py"""

import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
import propertybag as pb

PLUGIN_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "authwert", "etc", "auth-htpasswd.py",
)


def _load_plugin(ht_mock):
    apache_mod = MagicMock()
    apache_mod.HtpasswdFile = ht_mock

    with patch.dict(sys.modules, {
        "passlib": MagicMock(),
        "passlib.apache": apache_mod,
    }):
        from importlib.machinery import SourceFileLoader
        loader = SourceFileLoader("htpasswd_auth", PLUGIN_PATH)
        spec = importlib.util.spec_from_loader("htpasswd_auth", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
    return mod


def _make_ctx(path="/etc/authwert/.htpasswd"):
    ctx = pb.Bag({})
    ctx.authparams = path
    return ctx


@pytest.fixture
def ht_mock():
    return MagicMock()


@pytest.fixture
def plugin(ht_mock):
    return _load_plugin(ht_mock)


# ---------------------------------------------------------------------------
# init()

class TestInit:

    def test_stores_path(self, ht_mock):
        plugin = _load_plugin(ht_mock)
        ctx = _make_ctx("/etc/htpasswd")
        plugin.init(ctx)
        assert ctx.dbinf.path == "/etc/htpasswd"

    def test_strips_whitespace_from_path(self, ht_mock):
        plugin = _load_plugin(ht_mock)
        ctx = _make_ctx("  /etc/htpasswd  ")
        plugin.init(ctx)
        assert ctx.dbinf.path == "/etc/htpasswd"

    def test_creates_htpasswd_file_object(self, ht_mock):
        plugin = _load_plugin(ht_mock)
        ctx = _make_ctx("/etc/htpasswd")
        plugin.init(ctx)
        ht_mock.assert_called_once_with("/etc/htpasswd")

    def test_stores_ht_object(self, ht_mock):
        plugin = _load_plugin(ht_mock)
        ctx = _make_ctx("/etc/htpasswd")
        plugin.init(ctx)
        assert ctx.dbinf.ht is ht_mock.return_value


# ---------------------------------------------------------------------------
# verify()

class TestVerify:

    def _setup(self, ht_mock, check_result):
        plugin = _load_plugin(ht_mock)
        ht_mock.return_value.check_password.return_value = check_result
        ctx = _make_ctx()
        plugin.init(ctx)
        return plugin, ctx

    def test_valid_credentials_returns_true(self, ht_mock):
        plugin, ctx = self._setup(ht_mock, True)
        assert plugin.verify(ctx, "alice", "correctpw") is True

    def test_wrong_password_returns_false(self, ht_mock):
        plugin, ctx = self._setup(ht_mock, False)
        assert plugin.verify(ctx, "alice", "wrongpw") is False

    def test_unknown_user_returns_none_as_false(self, ht_mock):
        plugin, ctx = self._setup(ht_mock, None)
        assert plugin.verify(ctx, "nobody", "pw") is False

    def test_calls_load_if_changed_before_check(self, ht_mock):
        plugin, ctx = self._setup(ht_mock, True)
        plugin.verify(ctx, "alice", "pw")
        ht_mock.return_value.load_if_changed.assert_called_once()

    def test_exception_returns_false(self, ht_mock):
        plugin = _load_plugin(ht_mock)
        ht_mock.return_value.check_password.side_effect = OSError("file missing")
        ctx = _make_ctx()
        plugin.init(ctx)
        assert plugin.verify(ctx, "alice", "pw") is False

    def test_passes_uid_and_secret_to_check(self, ht_mock):
        plugin, ctx = self._setup(ht_mock, True)
        plugin.verify(ctx, "bob", "mypw")
        ht_mock.return_value.check_password.assert_called_once_with("bob", "mypw")


# ---------------------------------------------------------------------------
# close()

class TestClose:

    def test_close_does_not_raise(self, plugin):
        ctx = _make_ctx()
        plugin.init(ctx)
        plugin.close(ctx)  # should not raise

    def test_close_without_init_does_not_raise(self, plugin):
        ctx = _make_ctx()
        plugin.close(ctx)
