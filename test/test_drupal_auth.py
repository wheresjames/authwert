"""Tests for authwert/etc/auth-drupal.py"""

import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
import propertybag as pb

PLUGIN_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "authwert", "etc", "auth-drupal.py",
)


class FakeOperationalError(Exception):
    pass


def _load_plugin(phpass_verify_result=False):
    phpass_mock = MagicMock()
    phpass_mock.verify.return_value = phpass_verify_result

    passlib_mod = MagicMock()
    passlib_hash_mod = MagicMock()
    passlib_hash_mod.phpass = phpass_mock
    passlib_mod.hash = passlib_hash_mod

    with patch.dict(sys.modules, {
        "passlib": passlib_mod,
        "passlib.hash": passlib_hash_mod,
    }):
        from importlib.machinery import SourceFileLoader
        loader = SourceFileLoader("drupal_auth", PLUGIN_PATH)
        spec = importlib.util.spec_from_loader("drupal_auth", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
    return mod, phpass_mock


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
    cur.__enter__ = MagicMock(return_value=cur)
    cur.__exit__ = MagicMock(return_value=False)
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
            ctx = _make_ctx("mariadb://u:p@localhost/drupal")
            plugin.init(ctx)
        assert ctx.dbinf.database == "drupal"

    def test_default_table_is_users_field_data_for_d8(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/drupal")
            plugin.init(ctx)
        assert ctx.dbinf.table == "users_field_data"

    def test_drupal7_uses_users_table(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/drupal?version=7")
            plugin.init(ctx)
        assert ctx.dbinf.table == "users"

    def test_custom_table_from_query(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/drupal?table=myusers")
            plugin.init(ctx)
        assert ctx.dbinf.table == "myusers"

    def test_raises_on_missing_database(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/")
            with pytest.raises(ValueError, match="No database name"):
                plugin.init(ctx)

    def test_raises_on_unsupported_scheme(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("sqlite:///drupal.db")
        with pytest.raises(ValueError, match="Unsupported scheme"):
            plugin.init(ctx)

    def test_mariadb_placeholder_is_question_mark(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/drupal")
            plugin.init(ctx)
        assert ctx.dbinf.placeholder == "?"


# ---------------------------------------------------------------------------
# verify()

class TestVerify:

    def _setup(self, rows, phpass_result=False):
        plugin, phpass_mock = _load_plugin(phpass_result)
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        mariadb_mock.connect.return_value = conn
        _make_cursor(conn, rows)
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/drupal")
            plugin.init(ctx)
        return plugin, ctx, phpass_mock

    def test_valid_credentials_returns_true(self):
        plugin, ctx, _ = self._setup([("$P$hashed",)], phpass_result=True)
        assert plugin.verify(ctx, "alice", "correctpw") is True

    def test_wrong_password_returns_false(self):
        plugin, ctx, _ = self._setup([("$P$hashed",)], phpass_result=False)
        assert plugin.verify(ctx, "alice", "wrongpw") is False

    def test_unknown_user_returns_false(self):
        plugin, ctx, _ = self._setup([])
        assert plugin.verify(ctx, "nobody", "pw") is False

    def test_queries_by_name_and_mail(self):
        plugin, ctx, _ = self._setup([], phpass_result=False)
        plugin.verify(ctx, "alice@example.com", "pw")
        cur = ctx.dbinf.conn.cursor.return_value
        params = cur.execute.call_args.args[1]
        assert params == ("alice@example.com", "alice@example.com")

    def test_table_name_in_query(self):
        plugin, ctx, _ = self._setup([("$P$h",)], phpass_result=True)
        plugin.verify(ctx, "alice", "pw")
        cur = ctx.dbinf.conn.cursor.return_value
        sql = cur.execute.call_args.args[0]
        assert "users_field_data" in sql

    def test_exception_returns_false(self):
        plugin, ctx, _ = self._setup([])
        ctx.dbinf.conn.cursor.side_effect = RuntimeError("boom")
        assert plugin.verify(ctx, "alice", "pw") is False

    def test_reconnects_on_operational_error(self):
        plugin, phpass_mock = _load_plugin(True)
        phpass_mock.verify.return_value = True
        mariadb_mock = _make_mariadb_mock()

        cur = MagicMock()
        cur.__enter__ = MagicMock(return_value=cur)
        cur.__exit__ = MagicMock(return_value=False)
        cur.__iter__ = MagicMock(return_value=iter([("$P$h",)]))

        conn1 = MagicMock()
        conn1.cursor.side_effect = FakeOperationalError("lost")
        conn2 = MagicMock()
        conn2.cursor.return_value = cur

        mariadb_mock.connect.side_effect = [conn1, conn2]

        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/drupal")
            plugin.init(ctx)
            assert plugin.verify(ctx, "alice", "pw") is True
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
            ctx = _make_ctx("mariadb://u:p@localhost/drupal")
            plugin.init(ctx)
        plugin.close(ctx)
        conn.close.assert_called_once()

    def test_close_sets_conn_to_none(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        mariadb_mock.connect.return_value = MagicMock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/drupal")
            plugin.init(ctx)
        plugin.close(ctx)
        assert ctx.dbinf.conn is None

    def test_close_when_never_inited_does_not_raise(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("mariadb://u:p@localhost/drupal")
        plugin.close(ctx)
