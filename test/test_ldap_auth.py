"""Tests for authwert/etc/auth-ldap.py"""

import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch, call

import pytest
import propertybag as pb

PLUGIN_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "authwert", "etc", "auth-ldap.py",
)


class FakeLDAPException(Exception):
    pass


def _load_plugin():
    ldap3_mod = MagicMock()
    ldap3_mod.LDAPException = FakeLDAPException
    ldap3_mod.NONE = "NONE"
    ldap3_mod.AUTO_BIND_TLS_BEFORE_BIND = "tls"
    ldap3_mod.AUTO_BIND_NO_TLS = "no_tls"

    ldap3_exceptions = MagicMock()
    ldap3_exceptions.LDAPException = FakeLDAPException

    with patch.dict(sys.modules, {
        "ldap3": ldap3_mod,
        "ldap3.core": MagicMock(),
        "ldap3.core.exceptions": ldap3_exceptions,
    }):
        from importlib.machinery import SourceFileLoader
        loader = SourceFileLoader("ldap_auth", PLUGIN_PATH)
        spec = importlib.util.spec_from_loader("ldap_auth", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
    return mod, ldap3_mod


def _make_ctx(authparams):
    ctx = pb.Bag({})
    ctx.authparams = authparams
    return ctx


# ---------------------------------------------------------------------------
# init()

class TestInit:

    def test_sets_base_dn(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("ldap://bind:pw@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        assert ctx.dbinf.base_dn == "dc=example,dc=com"

    def test_sets_bind_dn(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("ldap://svc_bind:secret@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        assert ctx.dbinf.bind_dn == "svc_bind"

    def test_sets_bind_pw(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("ldap://svc:mysecret@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        assert ctx.dbinf.bind_pw == "mysecret"

    def test_default_filter(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("ldap://u:p@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        assert '{uid}' in ctx.dbinf.filter_tmpl

    def test_custom_filter_from_query(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("ldap://u:p@ldap.example.com/dc=example,dc=com?filter=(sAMAccountName%3D{uid})")
        plugin.init(ctx)
        assert 'sAMAccountName' in ctx.dbinf.filter_tmpl

    def test_ldap_scheme_not_ssl(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("ldap://u:p@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        assert ctx.dbinf.use_ssl is False

    def test_ldaps_scheme_sets_ssl(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("ldaps://u:p@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        assert ctx.dbinf.use_ssl is True

    def test_default_ldap_port_is_389(self):
        plugin, ldap3_mod = _load_plugin()
        ctx = _make_ctx("ldap://u:p@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        ldap3_mod.Server.assert_called_once()
        kwargs = ldap3_mod.Server.call_args.kwargs
        assert kwargs["port"] == 389

    def test_default_ldaps_port_is_636(self):
        plugin, ldap3_mod = _load_plugin()
        ctx = _make_ctx("ldaps://u:p@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        kwargs = ldap3_mod.Server.call_args.kwargs
        assert kwargs["port"] == 636

    def test_explicit_port_is_used(self):
        plugin, ldap3_mod = _load_plugin()
        ctx = _make_ctx("ldap://u:p@ldap.example.com:1389/dc=example,dc=com")
        plugin.init(ctx)
        kwargs = ldap3_mod.Server.call_args.kwargs
        assert kwargs["port"] == 1389

    def test_raises_on_unsupported_scheme(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("http://u:p@ldap.example.com/dc=example,dc=com")
        with pytest.raises(ValueError, match="Unsupported scheme"):
            plugin.init(ctx)

    def test_raises_on_missing_base_dn(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("ldap://u:p@ldap.example.com")
        with pytest.raises(ValueError, match="No base DN"):
            plugin.init(ctx)


# ---------------------------------------------------------------------------
# verify()

class TestVerify:

    def _make_entry(self, dn):
        e = MagicMock()
        e.entry_dn = dn
        return e

    def _setup(self, ldap3_mod, search_entries, bind_succeeds=True):
        conn_ctx = MagicMock()
        conn_ctx.__enter__ = MagicMock(return_value=conn_ctx)
        conn_ctx.__exit__ = MagicMock(return_value=False)
        conn_ctx.entries = search_entries

        if bind_succeeds:
            bind_ctx = MagicMock()
            bind_ctx.__enter__ = MagicMock(return_value=bind_ctx)
            bind_ctx.__exit__ = MagicMock(return_value=False)
        else:
            bind_ctx = MagicMock()
            bind_ctx.__enter__ = MagicMock(side_effect=FakeLDAPException("invalid creds"))

        ldap3_mod.Connection.side_effect = [conn_ctx, bind_ctx]
        return conn_ctx, bind_ctx

    def test_valid_user_returns_true(self):
        plugin, ldap3_mod = _load_plugin()
        ctx = _make_ctx("ldap://bind:pw@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        entry = self._make_entry("uid=alice,dc=example,dc=com")
        self._setup(ldap3_mod, [entry], bind_succeeds=True)
        assert plugin.verify(ctx, "alice", "correctpw") is True

    def test_wrong_password_returns_false(self):
        plugin, ldap3_mod = _load_plugin()
        ctx = _make_ctx("ldap://bind:pw@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        entry = self._make_entry("uid=alice,dc=example,dc=com")
        self._setup(ldap3_mod, [entry], bind_succeeds=False)
        assert plugin.verify(ctx, "alice", "wrongpw") is False

    def test_unknown_user_returns_false(self):
        plugin, ldap3_mod = _load_plugin()
        ctx = _make_ctx("ldap://bind:pw@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        self._setup(ldap3_mod, [], bind_succeeds=False)
        assert plugin.verify(ctx, "nobody", "pw") is False

    def test_uid_special_chars_are_stripped(self):
        plugin, ldap3_mod = _load_plugin()
        ctx = _make_ctx("ldap://bind:pw@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        conn_ctx = MagicMock()
        conn_ctx.__enter__ = MagicMock(return_value=conn_ctx)
        conn_ctx.__exit__ = MagicMock(return_value=False)
        conn_ctx.entries = []
        ldap3_mod.Connection.return_value = conn_ctx
        plugin.verify(ctx, "ali*(ce)\x00", "pw")
        search_call = conn_ctx.search.call_args
        assert "ali*(ce)\x00" not in str(search_call)

    def test_exception_in_search_returns_false(self):
        plugin, ldap3_mod = _load_plugin()
        ctx = _make_ctx("ldap://bind:pw@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        ldap3_mod.Connection.side_effect = RuntimeError("network error")
        assert plugin.verify(ctx, "alice", "pw") is False

    def test_tries_all_entries_before_giving_up(self):
        plugin, ldap3_mod = _load_plugin()
        ctx = _make_ctx("ldap://bind:pw@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)

        e1 = self._make_entry("uid=alice1,dc=example,dc=com")
        e2 = self._make_entry("uid=alice2,dc=example,dc=com")

        search_ctx = MagicMock()
        search_ctx.__enter__ = MagicMock(return_value=search_ctx)
        search_ctx.__exit__ = MagicMock(return_value=False)
        search_ctx.entries = [e1, e2]

        fail_bind = MagicMock()
        fail_bind.__enter__ = MagicMock(side_effect=FakeLDAPException("bad"))

        ok_bind = MagicMock()
        ok_bind.__enter__ = MagicMock(return_value=ok_bind)
        ok_bind.__exit__ = MagicMock(return_value=False)

        ldap3_mod.Connection.side_effect = [search_ctx, fail_bind, ok_bind]
        assert plugin.verify(ctx, "alice", "pw") is True


# ---------------------------------------------------------------------------
# close()

class TestClose:

    def test_close_does_not_raise(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("ldap://u:p@ldap.example.com/dc=example,dc=com")
        plugin.init(ctx)
        plugin.close(ctx)

    def test_close_without_init_does_not_raise(self):
        plugin, _ = _load_plugin()
        ctx = _make_ctx("ldap://u:p@ldap.example.com/dc=example,dc=com")
        plugin.close(ctx)
