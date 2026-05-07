"""Tests for authwert/etc/auth-nextcloud.py"""

import importlib.util
import os
import sys
import hashlib
from unittest.mock import MagicMock, patch

import pytest
import propertybag as pb

PLUGIN_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "authwert", "etc", "auth-nextcloud.py",
)


class FakeOperationalError(Exception):
    pass


def _load_plugin(bcrypt_result=False):
    bcrypt_mock = MagicMock()
    bcrypt_mock.verify.return_value = bcrypt_result

    passlib_mod = MagicMock()
    passlib_hash_mod = MagicMock()
    passlib_hash_mod.bcrypt = bcrypt_mock
    passlib_mod.hash = passlib_hash_mod

    with patch.dict(sys.modules, {
        "passlib": passlib_mod,
        "passlib.hash": passlib_hash_mod,
    }):
        from importlib.machinery import SourceFileLoader
        loader = SourceFileLoader("nextcloud_auth", PLUGIN_PATH)
        spec = importlib.util.spec_from_loader("nextcloud_auth", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
    return mod, bcrypt_mock


def _make_mariadb_mock():
    m = MagicMock()
    m.OperationalError = FakeOperationalError
    return m


def _make_ctx(authparams):
    ctx = pb.Bag({})
    ctx.authparams = authparams
    return ctx


def _make_cursor(conn_mock, rows):
    cur = MagicMock()
    cur.__iter__ = MagicMock(return_value=iter(rows))
    conn_mock.cursor.return_value = cur
    return cur


# ---------------------------------------------------------------------------
# init()

class TestInit:

    def test_sets_database_name(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/nextcloud")
            plugin.init(ctx)
        assert ctx.dbinf.database == "nextcloud"

    def test_default_table_is_oc_users(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/nextcloud")
            plugin.init(ctx)
        assert ctx.dbinf.table == "oc_users"

    def test_custom_prefix(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/nextcloud?prefix=nc_")
            plugin.init(ctx)
        assert ctx.dbinf.table == "nc_users"

    def test_sqlite_path(self):
        plugin, _ = _load_plugin()
        sqlite3_mock = MagicMock()
        sqlite3_mock.OperationalError = FakeOperationalError
        with patch.dict(sys.modules, {"sqlite3": sqlite3_mock}):
            ctx = _make_ctx("sqlite:////var/nextcloud/data/owncloud.db")
            plugin.init(ctx)
        assert "owncloud.db" in ctx.dbinf.database

    def test_raises_on_missing_database(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/")
            with pytest.raises(ValueError, match="No database name"):
                plugin.init(ctx)

    def test_raises_on_unsupported_scheme(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("ftp://u:p@localhost/nextcloud")
        with pytest.raises(ValueError, match="Unsupported scheme"):
            plugin.init(ctx)


# ---------------------------------------------------------------------------
# _check_password() (exercised via verify)

class TestCheckPassword:

    def _run_verify(self, plugin, ctx, stored_hash, bcrypt_mock, secret="pw"):
        _make_cursor(ctx.dbinf.conn, [(stored_hash,)])
        return plugin.verify(ctx, "alice", secret)

    def _make_ctx_with_conn(self, plugin, bcrypt_result):
        plugin, bcrypt_mock = _load_plugin(bcrypt_result)
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        mariadb_mock.connect.return_value = conn
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/nextcloud")
            plugin.init(ctx)
        return plugin, ctx, bcrypt_mock

    def test_bcrypt_2y_hash_verified(self):
        plugin, ctx, bcrypt_mock = self._make_ctx_with_conn(None, True)
        _make_cursor(ctx.dbinf.conn, [("$2y$10$abc",)])
        assert plugin.verify(ctx, "alice", "pw") is True
        bcrypt_mock.verify.assert_called_once()
        used_hash = bcrypt_mock.verify.call_args.args[1]
        assert used_hash.startswith("$2b$")

    def test_sha1_hex_hash_verified(self):
        secret = "testpassword"
        sha1 = hashlib.sha1(secret.encode()).hexdigest()
        plugin, ctx, bcrypt_mock = self._make_ctx_with_conn(None, False)
        _make_cursor(ctx.dbinf.conn, [(sha1,)])
        assert plugin.verify(ctx, "alice", secret) is True

    def test_wrong_sha1_returns_false(self):
        sha1 = hashlib.sha1(b"correctpw").hexdigest()
        plugin, ctx, bcrypt_mock = self._make_ctx_with_conn(None, False)
        _make_cursor(ctx.dbinf.conn, [(sha1,)])
        assert plugin.verify(ctx, "alice", "wrongpw") is False

    def test_md5_hex_hash_verified(self):
        import hashlib
        secret = "testpassword"
        md5 = hashlib.md5(secret.encode()).hexdigest()
        plugin, ctx, bcrypt_mock = self._make_ctx_with_conn(None, False)
        _make_cursor(ctx.dbinf.conn, [(md5,)])
        assert plugin.verify(ctx, "alice", secret) is True

    def test_unknown_hash_format_returns_false(self):
        plugin, ctx, bcrypt_mock = self._make_ctx_with_conn(None, False)
        _make_cursor(ctx.dbinf.conn, [("not_a_real_hash",)])
        assert plugin.verify(ctx, "alice", "pw") is False


# ---------------------------------------------------------------------------
# verify()

class TestVerify:

    def test_valid_bcrypt_returns_true(self):
        plugin, bcrypt_mock = _load_plugin(True)
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        mariadb_mock.connect.return_value = conn
        _make_cursor(conn, [("$2b$10$abc",)])
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/nextcloud")
            plugin.init(ctx)
        assert plugin.verify(ctx, "alice", "correctpw") is True

    def test_unknown_user_returns_false(self):
        plugin, bcrypt_mock = _load_plugin(False)
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        mariadb_mock.connect.return_value = conn
        _make_cursor(conn, [])
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/nextcloud")
            plugin.init(ctx)
        assert plugin.verify(ctx, "nobody", "pw") is False

    def test_exception_returns_false(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        conn.cursor.side_effect = RuntimeError("boom")
        mariadb_mock.connect.return_value = conn
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/nextcloud")
            plugin.init(ctx)
        assert plugin.verify(ctx, "alice", "pw") is False


# ---------------------------------------------------------------------------
# close()

class TestClose:

    def test_close_calls_conn_close(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        mariadb_mock.connect.return_value = conn
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/nextcloud")
            plugin.init(ctx)
        plugin.close(ctx)
        conn.close.assert_called_once()

    def test_close_sets_conn_to_none(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        mariadb_mock.connect.return_value = MagicMock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/nextcloud")
            plugin.init(ctx)
        plugin.close(ctx)
        assert ctx.dbinf.conn is None

    def test_close_when_never_inited_does_not_raise(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("mariadb://u:p@localhost/nextcloud")
        plugin.close(ctx)
