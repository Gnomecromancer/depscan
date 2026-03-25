"""Tests for depscan.checkers."""
from __future__ import annotations

from unittest.mock import patch, MagicMock, patch as mock_patch

from depscan.parsers import Dep
from depscan.checkers import (
    check,
    _is_outdated,
    _version_tuple,
    CheckResult,
)


# ── _version_tuple ─────────────────────────────────────────────────────────

def test_version_tuple_simple():
    assert _version_tuple("1.2.3") == (1, 2, 3)


def test_version_tuple_with_prerelease():
    # non-numeric parts become 0
    assert _version_tuple("1.0.0-alpha")[0] == 1


def test_version_tuple_two_parts():
    assert _version_tuple("18.2") == (18, 2)


# ── _is_outdated ──────────────────────────────────────────────────────────

def test_is_outdated_when_newer_available():
    assert _is_outdated("1.0.0", "2.0.0") is True


def test_is_not_outdated_when_current():
    assert _is_outdated("2.0.0", "2.0.0") is False


def test_is_not_outdated_when_none():
    assert _is_outdated(None, "2.0.0") is False
    assert _is_outdated("1.0.0", None) is False


def test_is_outdated_patch_bump():
    assert _is_outdated("1.0.0", "1.0.1") is True


# ── check() ───────────────────────────────────────────────────────────────

def _dep(name="requests", version="2.28.0", ecosystem="pypi"):
    return Dep(name=name, version=version, ecosystem=ecosystem)


def test_check_outdated():
    deps = [_dep(version="2.28.0")]
    with patch.dict("depscan.checkers._LATEST", {"pypi": lambda _: "2.31.0"}), \
         patch("depscan.checkers._query_osv", return_value=[]):
        results = check(deps)
    assert len(results) == 1
    r = results[0]
    assert r.is_outdated is True
    assert r.latest == "2.31.0"
    assert r.vulns == []


def test_check_up_to_date():
    deps = [_dep(version="2.31.0")]
    with patch.dict("depscan.checkers._LATEST", {"pypi": lambda _: "2.31.0"}), \
         patch("depscan.checkers._query_osv", return_value=[]):
        results = check(deps)
    assert results[0].is_outdated is False


def test_check_with_vulns():
    deps = [_dep()]
    with patch.dict("depscan.checkers._LATEST", {"pypi": lambda _: "2.31.0"}), \
         patch("depscan.checkers._query_osv", return_value=["CVE-2023-12345"]):
        results = check(deps)
    assert "CVE-2023-12345" in results[0].vulns


def test_check_skip_vulns():
    deps = [_dep()]
    with patch.dict("depscan.checkers._LATEST", {"pypi": lambda _: "2.31.0"}), \
         patch("depscan.checkers._query_osv") as mock_osv:
        results = check(deps, skip_vulns=True)
    mock_osv.assert_not_called()
    assert results[0].vulns == []


def test_check_unknown_ecosystem():
    deps = [Dep(name="something", version="1.0", ecosystem="unknown")]
    with patch("depscan.checkers._query_osv", return_value=[]):
        results = check(deps)
    assert results[0].latest is None
    assert results[0].is_outdated is False


def test_check_npm():
    deps = [Dep(name="react", version="17.0.0", ecosystem="npm")]
    with patch.dict("depscan.checkers._LATEST", {"npm": lambda _: "18.2.0"}), \
         patch("depscan.checkers._query_osv", return_value=[]):
        results = check(deps)
    assert results[0].is_outdated is True
    assert results[0].latest == "18.2.0"


def test_check_cargo():
    deps = [Dep(name="serde", version="1.0.100", ecosystem="cargo")]
    with patch.dict("depscan.checkers._LATEST", {"cargo": lambda _: "1.0.195"}), \
         patch("depscan.checkers._query_osv", return_value=[]):
        results = check(deps)
    assert results[0].is_outdated is True


def test_check_returns_dep_reference():
    d = _dep()
    with patch.dict("depscan.checkers._LATEST", {"pypi": lambda _: "2.31.0"}), \
         patch("depscan.checkers._query_osv", return_value=[]):
        results = check([d])
    assert results[0].dep is d
