"""Tests for authwert/etc/auth-wordpress.py"""

import importlib.util
import os
import sys
import types
from unittest.mock import MagicMock, patch, call

import pytest
import propertybag as pb

# ---------------------------------------------------------------------------
# Load the plugin module, mocking mariadb and passlib which may not be present

PLUGIN_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "authwert", "etc", "auth-wordpress.py",
)


def _load_plugin(mariadb_mock, phpass_mock):
    """Reload the plugin with the given mariadb/phpass mocks injected."""
    mariadb_mod = MagicMock()
    mariadb_mod.OperationalError = mariadb_mock.OperationalError

    passlib_mod = MagicMock()
    passlib_mod.hash.phpass = phpass_mock

    with patch.dict(sys.modules, {
        "mariadb": mariadb_mod,
        "passlib": passlib_mod,
        "passlib.hash": passlib_mod.hash,
    }):
        from importlib.machinery import SourceFileLoader
        loader = SourceFileLoader("wp_auth", PLUGIN_PATH)
        spec = importlib.util.spec_from_loader("wp_auth", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
    return mod, mariadb_mod


# ---------------------------------------------------------------------------
# Fixtures

class FakeOperationalError(Exception):
    pass


@pytest.fixture
def mariadb_mock():
    m = MagicMock()
    m.OperationalError = FakeOperationalError
    return m


@pytest.fixture
def phpass_mock():
    return MagicMock()


@pytest.fixture
def plugin(mariadb_mock, phpass_mock):
    mod, _ = _load_plugin(mariadb_mock, phpass_mock)
    return mod


@pytest.fixture
def plugin_and_db(mariadb_mock, phpass_mock):
    mod, mariadb_mod = _load_plugin(mariadb_mock, phpass_mock)
    return mod, mariadb_mod


def _make_ctx(authparams):
    ctx = pb.Bag({})
    ctx.authparams = authparams
    return ctx


def _inited_ctx(plugin, authparams="mariadb://user:pass@localhost/wordpress"):
    ctx = _make_ctx(authparams)
    plugin.init(ctx)
    return ctx


# ---------------------------------------------------------------------------
# init()

class TestInit:

    def test_sets_database_name(self, plugin):
        ctx = _make_ctx("mariadb://u:p@localhost/mydb")
        plugin.init(ctx)
        assert ctx.dbinf.database == "mydb"

    def test_default_prefix_is_wp(self, plugin):
        ctx = _make_ctx("mariadb://u:p@localhost/wordpress")
        plugin.init(ctx)
        assert ctx.dbinf.prefix == "wp_"

    def test_custom_prefix_from_query_string(self, plugin):
        ctx = _make_ctx("mariadb://u:p@localhost/wordpress?prefix=blog_")
        plugin.init(ctx)
        assert ctx.dbinf.prefix == "blog_"

    def test_raises_on_unsupported_scheme(self, plugin):
        ctx = _make_ctx("mysql://u:p@localhost/db")
        with pytest.raises(ValueError, match="Unsupported scheme"):
            plugin.init(ctx)

    def test_raises_on_missing_database(self, plugin):
        ctx = _make_ctx("mariadb://u:p@localhost")
        with pytest.raises(ValueError, match="No database name"):
            plugin.init(ctx)

    def test_raises_on_empty_path(self, plugin):
        ctx = _make_ctx("mariadb://u:p@localhost/")
        with pytest.raises(ValueError, match="No database name"):
            plugin.init(ctx)

    def test_connects_with_correct_credentials(self, plugin_and_db):
        plugin, mariadb_mod = plugin_and_db
        ctx = _make_ctx("mariadb://alice:s3cr3t@db.host/wordpress")
        plugin.init(ctx)
        mariadb_mod.connect.assert_called_once()
        kwargs = mariadb_mod.connect.call_args.kwargs
        assert kwargs["user"] == "alice"
        assert kwargs["password"] == "s3cr3t"
        assert kwargs["host"] == "db.host"
        assert kwargs["database"] == "wordpress"

    def test_default_port_is_3306(self, plugin_and_db):
        plugin, mariadb_mod = plugin_and_db
        ctx = _make_ctx("mariadb://u:p@localhost/db")
        plugin.init(ctx)
        kwargs = mariadb_mod.connect.call_args.kwargs
        assert kwargs["port"] == 3306

    def test_explicit_port_is_used(self, plugin_and_db):
        plugin, mariadb_mod = plugin_and_db
        ctx = _make_ctx("mariadb://u:p@localhost:3307/db")
        plugin.init(ctx)
        kwargs = mariadb_mod.connect.call_args.kwargs
        assert kwargs["port"] == 3307

    def test_connect_timeout_is_set(self, plugin_and_db):
        plugin, mariadb_mod = plugin_and_db
        ctx = _make_ctx("mariadb://u:p@localhost/db")
        plugin.init(ctx)
        kwargs = mariadb_mod.connect.call_args.kwargs
        assert "connect_timeout" in kwargs
        assert kwargs["connect_timeout"] > 0

    def test_conn_is_none_before_connect_succeeds(self, plugin_and_db):
        plugin, mariadb_mod = plugin_and_db
        mariadb_mod.connect.side_effect = FakeOperationalError("refused")
        ctx = _make_ctx("mariadb://u:p@localhost/db")
        with pytest.raises(FakeOperationalError):
            plugin.init(ctx)
        assert ctx.dbinf.conn is None


# ---------------------------------------------------------------------------
# verify()

class TestVerify:

    def _setup_cursor(self, plugin_and_db, rows, authparams="mariadb://u:p@h/db"):
        plugin, mariadb_mod = plugin_and_db
        cur = MagicMock()
        cur.__enter__ = MagicMock(return_value=cur)
        cur.__exit__ = MagicMock(return_value=False)
        cur.__iter__ = MagicMock(return_value=iter(rows))
        mariadb_mod.connect.return_value.cursor.return_value = cur
        ctx = _inited_ctx(plugin, authparams)
        return plugin, ctx, cur

    def test_valid_credentials_returns_true(self, plugin_and_db, phpass_mock):
        phpass_mock.verify.return_value = True
        plugin, ctx, _ = self._setup_cursor(plugin_and_db, [("$hashed$",)])
        assert plugin.verify(ctx, "alice", "correctpw") is True

    def test_wrong_password_returns_false(self, plugin_and_db, phpass_mock):
        phpass_mock.verify.return_value = False
        plugin, ctx, _ = self._setup_cursor(plugin_and_db, [("$hashed$",)])
        assert plugin.verify(ctx, "alice", "wrongpw") is False

    def test_unknown_user_returns_false(self, plugin_and_db, phpass_mock):
        plugin, ctx, _ = self._setup_cursor(plugin_and_db, [])
        assert plugin.verify(ctx, "nobody", "pw") is False

    def test_uses_default_table_wp_users(self, plugin_and_db, phpass_mock):
        phpass_mock.verify.return_value = True
        plugin, ctx, cur = self._setup_cursor(plugin_and_db, [("$h$",)])
        plugin.verify(ctx, "alice", "pw")
        sql = cur.execute.call_args.args[0]
        assert "wp_users" in sql

    def test_uses_custom_table_prefix(self, plugin_and_db, phpass_mock):
        phpass_mock.verify.return_value = True
        plugin, ctx, cur = self._setup_cursor(
            plugin_and_db, [("$h$",)],
            authparams="mariadb://u:p@h/db?prefix=blog_",
        )
        plugin.verify(ctx, "alice", "pw")
        sql = cur.execute.call_args.args[0]
        assert "blog_users" in sql

    def test_queries_by_username_and_email(self, plugin_and_db, phpass_mock):
        phpass_mock.verify.return_value = True
        plugin, ctx, cur = self._setup_cursor(plugin_and_db, [("$h$",)])
        plugin.verify(ctx, "alice@example.com", "pw")
        params = cur.execute.call_args.args[1]
        assert params == ("alice@example.com", "alice@example.com")

    def test_multiple_rows_checks_all(self, plugin_and_db, phpass_mock):
        # First row doesn't match, second does
        phpass_mock.verify.side_effect = [False, True]
        plugin, ctx, cur = self._setup_cursor(
            plugin_and_db, [("$h1$",), ("$h2$",)]
        )
        assert plugin.verify(ctx, "alice", "pw") is True
        assert phpass_mock.verify.call_count == 2

    def test_reconnects_on_operational_error(self, plugin_and_db, phpass_mock):
        plugin, mariadb_mod = plugin_and_db
        phpass_mock.verify.return_value = True

        cur = MagicMock()
        cur.__enter__ = MagicMock(return_value=cur)
        cur.__exit__ = MagicMock(return_value=False)
        cur.__iter__ = MagicMock(return_value=iter([("$h$",)]))

        # First cursor raises OperationalError; second (after reconnect) succeeds
        conn1 = MagicMock()
        conn1.cursor.side_effect = FakeOperationalError("lost connection")
        conn2 = MagicMock()
        conn2.cursor.return_value = cur
        mariadb_mod.connect.side_effect = [conn1, conn2]

        ctx = _make_ctx("mariadb://u:p@localhost/db")
        plugin.init(ctx)
        result = plugin.verify(ctx, "alice", "pw")
        assert result is True
        assert mariadb_mod.connect.call_count == 2

    def test_returns_false_when_reconnect_fails(self, plugin_and_db, phpass_mock):
        plugin, mariadb_mod = plugin_and_db

        conn1 = MagicMock()
        conn1.cursor.side_effect = FakeOperationalError("lost connection")
        mariadb_mod.connect.side_effect = [conn1, FakeOperationalError("still down")]

        ctx = _make_ctx("mariadb://u:p@localhost/db")
        plugin.init(ctx)
        result = plugin.verify(ctx, "alice", "pw")
        assert result is False

    def test_non_operational_error_does_not_reconnect(self, plugin_and_db, phpass_mock):
        plugin, mariadb_mod = plugin_and_db

        conn = MagicMock()
        conn.cursor.side_effect = RuntimeError("unexpected")
        mariadb_mod.connect.return_value = conn

        ctx = _make_ctx("mariadb://u:p@localhost/db")
        plugin.init(ctx)
        result = plugin.verify(ctx, "alice", "pw")
        assert result is False
        # connect() was called once (init) — no reconnect attempt
        assert mariadb_mod.connect.call_count == 1

    def test_phpass_error_does_not_reconnect(self, plugin_and_db, phpass_mock):
        plugin, mariadb_mod = plugin_and_db
        phpass_mock.verify.side_effect = ValueError("bad hash")

        cur = MagicMock()
        cur.__enter__ = MagicMock(return_value=cur)
        cur.__exit__ = MagicMock(return_value=False)
        cur.__iter__ = MagicMock(return_value=iter([("$bad$",)]))
        mariadb_mod.connect.return_value.cursor.return_value = cur

        ctx = _make_ctx("mariadb://u:p@localhost/db")
        plugin.init(ctx)
        result = plugin.verify(ctx, "alice", "pw")
        assert result is False
        assert mariadb_mod.connect.call_count == 1


# ---------------------------------------------------------------------------
# close()

class TestClose:

    def test_close_calls_conn_close(self, plugin_and_db):
        plugin, mariadb_mod = plugin_and_db
        conn = MagicMock()
        mariadb_mod.connect.return_value = conn
        ctx = _inited_ctx(plugin)
        plugin.close(ctx)
        conn.close.assert_called_once()

    def test_close_sets_conn_to_none(self, plugin_and_db):
        plugin, mariadb_mod = plugin_and_db
        ctx = _inited_ctx(plugin)
        plugin.close(ctx)
        assert ctx.dbinf.conn is None

    def test_close_when_conn_is_none_does_not_raise(self, plugin):
        ctx = _make_ctx("mariadb://u:p@localhost/db")
        ctx.dbinf.conn = None
        plugin.close(ctx)  # should not raise

    def test_close_when_conn_never_set_does_not_raise(self, plugin):
        ctx = _make_ctx("mariadb://u:p@localhost/db")
        # dbinf exists but conn attribute was never assigned
        plugin.close(ctx)  # should not raise
