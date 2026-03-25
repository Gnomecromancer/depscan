"""Tests for depscan.parsers."""
from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from depscan.parsers import parse, auto_find


# ── requirements.txt ─────────────────────────────────────────────────────────

def test_requirements_pinned(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests==2.31.0\nclick==8.1.3\n")
    deps = parse(f)
    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].version == "2.31.0"
    assert deps[0].ecosystem == "pypi"
    assert deps[1].name == "click"
    assert deps[1].version == "8.1.3"


def test_requirements_unpinned(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("requests>=2.0\nflask\n")
    deps = parse(f)
    assert len(deps) == 2
    assert deps[0].version is None
    assert deps[1].version is None


def test_requirements_extras_and_markers(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text('requests[security]==2.28.0; python_version>="3.8"\n')
    deps = parse(f)
    assert deps[0].name == "requests"
    assert deps[0].version == "2.28.0"


def test_requirements_skips_comments_and_flags(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text("# a comment\n-r other.txt\nrequests==2.31.0\n")
    deps = parse(f)
    assert len(deps) == 1
    assert deps[0].name == "requests"


# ── package.json ─────────────────────────────────────────────────────────────

def test_package_json_basic(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(json.dumps({
        "dependencies": {"react": "^18.2.0"},
        "devDependencies": {"jest": "~29.0.0"},
    }))
    deps = parse(f)
    assert len(deps) == 2
    names = {d.name for d in deps}
    assert "react" in names
    assert "jest" in names
    react = next(d for d in deps if d.name == "react")
    assert react.version == "18.2.0"
    assert react.ecosystem == "npm"


def test_package_json_exact_version(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(json.dumps({"dependencies": {"lodash": "4.17.21"}}))
    deps = parse(f)
    assert deps[0].version == "4.17.21"


def test_package_json_scoped(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(json.dumps({"dependencies": {"@babel/core": "7.20.0"}}))
    deps = parse(f)
    assert deps[0].name == "@babel/core"


# ── Cargo.toml ───────────────────────────────────────────────────────────────

def test_cargo_toml_string_spec(tmp_path):
    f = tmp_path / "Cargo.toml"
    f.write_text(textwrap.dedent("""\
        [dependencies]
        serde = "1.0.136"
        tokio = { version = "1.24", features = ["full"] }

        [dev-dependencies]
        proptest = "1.0"
    """))
    deps = parse(f)
    names = {d.name: d for d in deps}
    assert names["serde"].version == "1.0.136"
    assert names["tokio"].version == "1.24"
    assert names["proptest"].version == "1.0"
    for d in deps:
        assert d.ecosystem == "cargo"


# ── auto_find ─────────────────────────────────────────────────────────────────

def test_auto_find(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    (tmp_path / "package.json").write_text('{"dependencies": {}}')
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "Cargo.toml").write_text("[dependencies]\n")
    # Ignored directory
    nm = tmp_path / "node_modules"
    nm.mkdir()
    (nm / "package.json").write_text('{"dependencies": {}}')

    found = auto_find(tmp_path)
    names = {p.name for p in found}
    assert "requirements.txt" in names
    assert "package.json" in names
    assert "Cargo.toml" in names
    # node_modules must be excluded
    assert all("node_modules" not in str(p) for p in found)


def test_parse_unsupported_raises(tmp_path):
    f = tmp_path / "setup.py"
    f.write_text("")
    with pytest.raises(ValueError, match="Unsupported"):
        parse(f)
