"""Tests for depscan CLI."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from depscan.cli import main
from depscan.parsers import Dep
from depscan.checkers import CheckResult


def _make_result(name, version="1.0.0", ecosystem="pypi", latest=None,
                 is_outdated=False, vulns=None):
    dep = Dep(name=name, version=version, ecosystem=ecosystem)
    return CheckResult(
        dep=dep,
        latest=latest or version,
        is_outdated=is_outdated,
        vulns=vulns or [],
    )


def test_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_no_files_exits_nonzero():
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(main, [])
    assert result.exit_code == 1


def test_clean_scan_exits_zero(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n")
    results = [_make_result("requests", "2.31.0", latest="2.31.0")]
    runner = CliRunner()
    with patch("depscan.cli.parse", return_value=[results[0].dep]), \
         patch("depscan.cli.check", return_value=results):
        result = runner.invoke(main, [str(req), "--no-color"])
    assert result.exit_code == 0
    assert "all clear" in result.output


def test_outdated_scan_exits_one(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\n")
    results = [_make_result("requests", "2.28.0", latest="2.31.0", is_outdated=True)]
    runner = CliRunner()
    with patch("depscan.cli.parse", return_value=[results[0].dep]), \
         patch("depscan.cli.check", return_value=results):
        result = runner.invoke(main, [str(req), "--no-color"])
    assert result.exit_code == 1
    assert "→ 2.31.0" in result.output


def test_vuln_shows_cve(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\n")
    results = [_make_result("requests", "2.28.0", vulns=["CVE-2023-32681"])]
    runner = CliRunner()
    with patch("depscan.cli.parse", return_value=[results[0].dep]), \
         patch("depscan.cli.check", return_value=results):
        result = runner.invoke(main, [str(req), "--no-color"])
    assert result.exit_code == 1
    assert "CVE-2023-32681" in result.output


def test_skip_vulns_flag(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.0\n")
    dep = Dep(name="requests", version="2.28.0", ecosystem="pypi")
    clean_result = _make_result("requests", "2.28.0", latest="2.31.0", is_outdated=True)
    runner = CliRunner()
    with patch("depscan.cli.parse", return_value=[dep]), \
         patch("depscan.cli.check") as mock_check:
        mock_check.return_value = [clean_result]
        runner.invoke(main, [str(req), "--skip-vulns"])
    mock_check.assert_called_once_with([dep], skip_vulns=True)


def test_only_outdated_filter(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\nflask==2.3.0\n")
    results = [
        _make_result("requests", "2.31.0", latest="2.31.0"),
        _make_result("flask", "2.3.0", latest="3.0.0", is_outdated=True),
    ]
    runner = CliRunner()
    with patch("depscan.cli.parse", return_value=[r.dep for r in results]), \
         patch("depscan.cli.check", return_value=results):
        result = runner.invoke(main, [str(req), "--only-outdated", "--no-color"])
    assert "flask" in result.output
    assert "requests" not in result.output


def test_dir_flag(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n")
    dep = Dep(name="requests", version="2.31.0", ecosystem="pypi")
    clean_result = _make_result("requests", "2.31.0")
    runner = CliRunner()
    with patch("depscan.cli.auto_find", return_value=[req]) as mock_find, \
         patch("depscan.cli.parse", return_value=[dep]), \
         patch("depscan.cli.check", return_value=[clean_result]):
        result = runner.invoke(main, ["--dir", str(tmp_path), "--no-color"])
    mock_find.assert_called_once()
    assert result.exit_code == 0
