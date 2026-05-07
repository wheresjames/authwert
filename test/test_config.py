"""Tests for authwert.loadConfig and PROJECT.txt parsing."""

import os
import pytest
import authwert


def test_loadConfig_sets_known_keys(tmp_path):
    cfg = tmp_path / "proj.txt"
    cfg.write_text("name    mypackage\nversion 1.2.3\n")
    authwert.loadConfig(str(cfg))
    assert authwert.__info__["name"] == "mypackage"
    assert authwert.__info__["version"] == "1.2.3"


def test_loadConfig_ignores_comment_lines(tmp_path):
    cfg = tmp_path / "proj.txt"
    cfg.write_text("# this is a comment\nname testpkg\n")
    authwert.loadConfig(str(cfg))
    assert "#" not in authwert.__info__
    assert "this" not in authwert.__info__
    assert authwert.__info__["name"] == "testpkg"


def test_loadConfig_blank_lines_do_not_crash(tmp_path):
    cfg = tmp_path / "proj.txt"
    cfg.write_text("\n\nname blanktest\n\n")
    authwert.loadConfig(str(cfg))
    assert authwert.__info__["name"] == "blanktest"


def test_loadConfig_whitespace_only_lines_do_not_crash(tmp_path):
    cfg = tmp_path / "proj.txt"
    cfg.write_text("   \n\t\nname wstest\n")
    authwert.loadConfig(str(cfg))
    assert authwert.__info__["name"] == "wstest"


def test_loadConfig_value_with_spaces(tmp_path):
    cfg = tmp_path / "proj.txt"
    cfg.write_text("description A library for auth\n")
    authwert.loadConfig(str(cfg))
    assert authwert.__info__["description"] == "A library for auth"


def test_loadConfig_tab_separated(tmp_path):
    cfg = tmp_path / "proj.txt"
    cfg.write_text("name\ttabpkg\n")
    authwert.loadConfig(str(cfg))
    assert authwert.__info__["name"] == "tabpkg"


def test_loadConfig_resets_info_dict(tmp_path):
    cfg1 = tmp_path / "a.txt"
    cfg1.write_text("name first\n")
    cfg2 = tmp_path / "b.txt"
    cfg2.write_text("name second\n")
    authwert.loadConfig(str(cfg1))
    authwert.loadConfig(str(cfg2))
    assert authwert.__info__.get("name") == "second"
    assert len(authwert.__info__) == 1


def test_loadConfig_sets_dunder_globals(tmp_path):
    cfg = tmp_path / "proj.txt"
    cfg.write_text("version 9.9.9\n")
    authwert.loadConfig(str(cfg))
    assert authwert.__version__ == "9.9.9"


def test_loadConfig_empty_file_does_not_crash(tmp_path):
    cfg = tmp_path / "empty.txt"
    cfg.write_text("")
    authwert.loadConfig(str(cfg))
    assert authwert.__info__ == {}


def test_loadConfig_project_txt_is_readable():
    """The bundled PROJECT.txt must be parseable without errors."""
    proj = authwert.libPath("PROJECT.txt")
    assert os.path.isfile(proj)
    authwert.loadConfig(proj)
    assert "name" in authwert.__info__
    assert "version" in authwert.__info__
