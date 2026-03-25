"""Check packages against PyPI, npm registries and OSV vulnerability database."""
from __future__ import annotations
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Sequence

from .parsers import Dep


@dataclass
class CheckResult:
    dep: Dep
    latest: str | None = None
    is_outdated: bool = False
    vulns: list[str] = field(default_factory=list)   # CVE IDs
    error: str | None = None


def _http_get(url: str, *, timeout: int = 8) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "depscan/0.1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError):
        return None


# ── Latest version lookup ────────────────────────────────────────────────────

def _latest_pypi(name: str) -> str | None:
    data = _http_get(f"https://pypi.org/pypi/{name}/json")
    return data["info"]["version"] if data else None


def _latest_npm(name: str) -> str | None:
    # URL-encode scoped packages like @babel/core
    encoded = urllib.request.pathname2url(name)
    data = _http_get(f"https://registry.npmjs.org/{encoded}/latest")
    return data.get("version") if data else None


def _latest_cargo(name: str) -> str | None:
    data = _http_get(f"https://crates.io/api/v1/crates/{name}")
    if not data:
        return None
    return data.get("crate", {}).get("max_stable_version") or data.get("crate", {}).get("newest_version")


_LATEST = {
    "pypi": _latest_pypi,
    "npm": _latest_npm,
    "cargo": _latest_cargo,
}


# ── Vulnerability lookup (OSV) ────────────────────────────────────────────────

_OSV_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "cargo": "crates.io",
}


def _query_osv(name: str, version: str | None, ecosystem: str) -> list[str]:
    """Return list of CVE/GHSA IDs affecting this package version."""
    osv_eco = _OSV_ECOSYSTEM.get(ecosystem)
    if not osv_eco:
        return []

    payload = {
        "package": {"name": name, "ecosystem": osv_eco},
    }
    if version:
        payload["version"] = version

    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "depscan/0.1"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read())
    except Exception:
        return []

    ids = []
    for vuln in data.get("vulns", []):
        alias = vuln.get("aliases", [])
        cve = next((a for a in alias if a.startswith("CVE-")), vuln.get("id", ""))
        if cve:
            ids.append(cve)
    return ids


# ── Version comparison (simple: split on dots, compare ints) ─────────────────

def _version_tuple(v: str) -> tuple:
    parts = []
    for p in re.split(r"[.\-]", v):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    return tuple(parts)


import re


def _is_outdated(current: str | None, latest: str | None) -> bool:
    if current is None or latest is None:
        return False
    try:
        return _version_tuple(latest) > _version_tuple(current)
    except Exception:
        return False


# ── Main check ──────────────────────────────────────────────────────────────

def check(deps: Sequence[Dep], *, skip_vulns: bool = False) -> list[CheckResult]:
    results = []
    for dep in deps:
        latest_fn = _LATEST.get(dep.ecosystem)
        latest = latest_fn(dep.name) if latest_fn else None
        outdated = _is_outdated(dep.version, latest)

        vulns: list[str] = []
        if not skip_vulns and dep.ecosystem in _OSV_ECOSYSTEM:
            vulns = _query_osv(dep.name, dep.version, dep.ecosystem)

        results.append(CheckResult(dep=dep, latest=latest, is_outdated=outdated, vulns=vulns))

    return results
