"""Tests for authwert/etc/auth-django.py"""

import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
import propertybag as pb

PLUGIN_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "authwert", "etc", "auth-django.py",
)


class FakeOperationalError(Exception):
    pass


def _load_plugin(hasher_results=None):
    """Load the plugin with passlib hashers mocked out."""
    if hasher_results is None:
        hasher_results = {}

    def _make_hasher(name):
        h = MagicMock()
        h.verify.return_value = hasher_results.get(name, False)
        return h

    passlib_mod = MagicMock()
    passlib_hash_mod = MagicMock()
    passlib_hash_mod.django_pbkdf2_sha256 = _make_hasher('pbkdf2')
    passlib_hash_mod.django_bcrypt = _make_hasher('bcrypt')
    passlib_hash_mod.django_argon2 = _make_hasher('argon2')
    passlib_mod.hash = passlib_hash_mod

    with patch.dict(sys.modules, {
        "passlib": passlib_mod,
        "passlib.hash": passlib_hash_mod,
    }):
        from importlib.machinery import SourceFileLoader
        loader = SourceFileLoader("django_auth", PLUGIN_PATH)
        spec = importlib.util.spec_from_loader("django_auth", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
    return mod, passlib_hash_mod


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
            ctx = _make_ctx("mariadb://u:p@localhost/myapp")
            plugin.init(ctx)
        assert ctx.dbinf.database == "myapp"

    def test_default_table_is_auth_user(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/myapp")
            plugin.init(ctx)
        assert ctx.dbinf.table == "auth_user"

    def test_custom_table_from_query(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/myapp?table=myapp_users")
            plugin.init(ctx)
        assert ctx.dbinf.table == "myapp_users"

    def test_sqlite_path_used_as_database(self):
        plugin, _ = _load_plugin()
        sqlite3_mock = MagicMock()
        with patch.dict(sys.modules, {"sqlite3": sqlite3_mock}):
            ctx = _make_ctx("sqlite:////var/db/myapp.db")
            plugin.init(ctx)
        assert ctx.dbinf.database == "//var/db/myapp.db"

    def test_raises_on_missing_database_name(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/")
            with pytest.raises(ValueError, match="No database name"):
                plugin.init(ctx)

    def test_raises_on_unsupported_scheme(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("oracle://u:p@localhost/myapp")
        with pytest.raises((ValueError, Exception)):
            plugin.init(ctx)

    def test_mariadb_placeholder_is_question_mark(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/myapp")
            plugin.init(ctx)
        assert ctx.dbinf.placeholder == '?'


# ---------------------------------------------------------------------------
# verify()

class TestVerify:

    def _setup_mariadb(self, rows, hasher_results=None):
        plugin, hashers = _load_plugin(hasher_results or {})
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        mariadb_mock.connect.return_value = conn
        _make_cursor(conn, rows)
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/myapp")
            plugin.init(ctx)
        return plugin, ctx, hashers

    def test_valid_pbkdf2_returns_true(self):
        plugin, ctx, _ = self._setup_mariadb(
            [("pbkdf2_sha256$...",)], hasher_results={"pbkdf2": True}
        )
        assert plugin.verify(ctx, "alice", "correctpw") is True

    def test_valid_bcrypt_returns_true(self):
        plugin, ctx, _ = self._setup_mariadb(
            [("bcrypt$$...",)], hasher_results={"bcrypt": True}
        )
        assert plugin.verify(ctx, "alice", "correctpw") is True

    def test_wrong_password_returns_false(self):
        plugin, ctx, _ = self._setup_mariadb(
            [("pbkdf2_sha256$...",)], hasher_results={"pbkdf2": False}
        )
        assert plugin.verify(ctx, "alice", "wrongpw") is False

    def test_unknown_user_returns_false(self):
        plugin, ctx, _ = self._setup_mariadb([], hasher_results={})
        assert plugin.verify(ctx, "nobody", "pw") is False

    def test_queries_by_username_and_email(self):
        plugin, ctx, _ = self._setup_mariadb([], hasher_results={})
        plugin.verify(ctx, "alice@example.com", "pw")
        cur = ctx.dbinf.conn.cursor.return_value
        params = cur.execute.call_args.args[1]
        assert params == ("alice@example.com", "alice@example.com")

    def test_tries_all_hashers(self):
        plugin, hashers = _load_plugin({"pbkdf2": False, "bcrypt": False, "argon2": True})
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        mariadb_mock.connect.return_value = conn
        _make_cursor(conn, [("$argon2$...",)])
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/myapp")
            plugin.init(ctx)
        assert plugin.verify(ctx, "alice", "pw") is True
        assert hashers.django_argon2.verify.called


# ---------------------------------------------------------------------------
# close()

class TestClose:

    def test_close_calls_conn_close(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        conn = MagicMock()
        mariadb_mock.connect.return_value = conn
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/myapp")
            plugin.init(ctx)
        plugin.close(ctx)
        conn.close.assert_called_once()

    def test_close_sets_conn_to_none(self):
        plugin, _ = _load_plugin()
        mariadb_mock = _make_mariadb_mock()
        mariadb_mock.connect.return_value = MagicMock()
        with patch.dict(sys.modules, {"mariadb": mariadb_mock}):
            ctx = _make_ctx("mariadb://u:p@localhost/myapp")
            plugin.init(ctx)
        plugin.close(ctx)
        assert ctx.dbinf.conn is None

    def test_close_when_conn_never_set_does_not_raise(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("mariadb://u:p@localhost/myapp")
        plugin.close(ctx)
