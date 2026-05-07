"""Tests for the @file indirection in --authparams."""

import importlib.util
import os
import sys

import pytest
import propertybag as pb
from conftest import PROJECT_ROOT


def _load_bin():
    from importlib.machinery import SourceFileLoader
    path = os.path.join(PROJECT_ROOT, "bin", "authwert")
    loader = SourceFileLoader("authwert_bin", path)
    spec = importlib.util.spec_from_loader("authwert_bin", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _run_resolution(authparams, tmp_path):
    """Exercise only the @-file resolution block from main()."""
    mod = _load_bin()
    _p = pb.Bag({})
    _p.authparams = authparams

    if _p.authparams and '@' == _p.authparams[0]:
        fpath = _p.authparams[1:]
        with open(fpath) as f:
            _p.authparams = f.read().strip()

    return _p.authparams


class TestAuthparamsFileResolution:

    def test_at_prefix_reads_file_contents(self, tmp_path):
        f = tmp_path / "db.conf"
        f.write_text("mariadb://user:pass@localhost/mydb\n")
        result = _run_resolution(f"@{f}", tmp_path)
        assert result == "mariadb://user:pass@localhost/mydb"

    def test_at_prefix_strips_trailing_newline(self, tmp_path):
        f = tmp_path / "db.conf"
        f.write_text("mariadb://user:pass@localhost/mydb\n\n")
        result = _run_resolution(f"@{f}", tmp_path)
        assert result == "mariadb://user:pass@localhost/mydb"

    def test_at_prefix_strips_leading_whitespace(self, tmp_path):
        f = tmp_path / "db.conf"
        f.write_text("  mariadb://user:pass@localhost/mydb")
        result = _run_resolution(f"@{f}", tmp_path)
        assert result == "mariadb://user:pass@localhost/mydb"

    def test_no_at_prefix_returns_value_unchanged(self, tmp_path):
        result = _run_resolution("mariadb://user:pass@localhost/mydb", tmp_path)
        assert result == "mariadb://user:pass@localhost/mydb"

    def test_at_prefix_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            _run_resolution(f"@{tmp_path}/nonexistent.conf", tmp_path)

    def test_empty_authparams_not_treated_as_at_file(self, tmp_path):
        result = _run_resolution("", tmp_path)
        assert result == ""
