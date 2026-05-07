"""Tests for authwert/etc/auth-ghost.py"""

import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
import propertybag as pb

PLUGIN_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "authwert", "etc", "auth-ghost.py",
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
        loader = SourceFileLoader("ghost_auth", PLUGIN_PATH)
        spec = importlib.util.spec_from_loader("ghost_auth", loader)
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

    def test_sets_database_name_mariadb(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/ghost")
            plugin.init(ctx)
        assert ctx.dbinf.database == "ghost"

    def test_sqlite_path_used_as_database(self):
        plugin, _ = _load_plugin()
        sqlite3_mock = MagicMock()
        sqlite3_mock.OperationalError = FakeOperationalError
        with patch.dict(sys.modules, {"sqlite3": sqlite3_mock}):
            ctx = _make_ctx("sqlite:////var/lib/ghost/content/data/ghost.db")
            plugin.init(ctx)
        assert "ghost.db" in ctx.dbinf.database

    def test_raises_on_missing_database_name(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/")
            with pytest.raises(ValueError, match="No database name"):
                plugin.init(ctx)

    def test_raises_on_unsupported_scheme(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("postgresql://u:p@localhost/ghost")
        with pytest.raises(ValueError, match="Unsupported scheme"):
            plugin.init(ctx)

    def test_mariadb_placeholder_is_question_mark(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/ghost")
            plugin.init(ctx)
        assert ctx.dbinf.placeholder == "?"


# ---------------------------------------------------------------------------
# verify()

class TestVerify:

    def _setup(self, rows, bcrypt_result=False):
        plugin, bcrypt_mock = _load_plugin(bcrypt_result)
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        mariadb_mock.connect.return_value = conn
        _make_cursor(conn, rows)
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/ghost")
            plugin.init(ctx)
        return plugin, ctx, bcrypt_mock

    def test_valid_credentials_returns_true(self):
        plugin, ctx, _ = self._setup([("$2b$10$abc",)], bcrypt_result=True)
        assert plugin.verify(ctx, "alice@example.com", "correctpw") is True

    def test_wrong_password_returns_false(self):
        plugin, ctx, _ = self._setup([("$2b$10$abc",)], bcrypt_result=False)
        assert plugin.verify(ctx, "alice@example.com", "wrongpw") is False

    def test_unknown_user_returns_false(self):
        plugin, ctx, _ = self._setup([])
        assert plugin.verify(ctx, "nobody@example.com", "pw") is False

    def test_queries_by_email(self):
        plugin, ctx, _ = self._setup([], bcrypt_result=False)
        plugin.verify(ctx, "alice@example.com", "pw")
        cur = ctx.dbinf.conn.cursor.return_value
        params = cur.execute.call_args.args[1]
        assert params == ("alice@example.com",)

    def test_2y_prefix_normalized_to_2b(self):
        plugin, ctx, bcrypt_mock = self._setup([("$2y$10$abc",)], bcrypt_result=True)
        plugin.verify(ctx, "alice@example.com", "pw")
        used_hash = bcrypt_mock.verify.call_args.args[1]
        assert used_hash.startswith("$2b$")

    def test_bcrypt_exception_skips_row(self):
        plugin, bcrypt_mock = _load_plugin(False)
        bcrypt_mock.verify.side_effect = ValueError("bad hash")
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        mariadb_mock.connect.return_value = conn
        _make_cursor(conn, [("$2b$10$abc",)])
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/ghost")
            plugin.init(ctx)
        assert plugin.verify(ctx, "alice@example.com", "pw") is False

    def test_exception_returns_false(self):
        plugin, ctx, _ = self._setup([])
        ctx.dbinf.conn.cursor.side_effect = RuntimeError("boom")
        assert plugin.verify(ctx, "alice@example.com", "pw") is False

    def test_reconnects_on_operational_error(self):
        plugin, bcrypt_mock = _load_plugin(True)
        mariadb_mock = _make_mariadb_mock()

        cur = MagicMock()
        cur.__iter__ = MagicMock(return_value=iter([("$2b$10$abc",)]))

        conn1 = MagicMock()
        conn1.cursor.side_effect = FakeOperationalError("lost")
        conn2 = MagicMock()
        conn2.cursor.return_value = cur

        mariadb_mock.connect.side_effect = [conn1, conn2]
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/ghost")
            plugin.init(ctx)
            assert plugin.verify(ctx, "alice@example.com", "pw") is True
        assert mariadb_mock.connect.call_count == 2


# ---------------------------------------------------------------------------
# close()

class TestClose:

    def test_close_calls_conn_close(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        mariadb_mock.connect.return_value = conn
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/ghost")
            plugin.init(ctx)
        plugin.close(ctx)
        conn.close.assert_called_once()

    def test_close_sets_conn_to_none(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        mariadb_mock.connect.return_value = MagicMock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/ghost")
            plugin.init(ctx)
        plugin.close(ctx)
        assert ctx.dbinf.conn is None

    def test_close_when_never_inited_does_not_raise(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("mariadb://u:p@localhost/ghost")
        plugin.close(ctx)
