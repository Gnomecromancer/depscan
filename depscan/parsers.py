"""Parse dependency files from various ecosystems."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Dep:
    name: str
    version: str | None    # None if not pinned
    ecosystem: str          # pypi | npm | cargo | go


# ── Python ──────────────────────────────────────────────────────────────────

def _parse_requirements_txt(path: Path) -> list[Dep]:
    deps = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip extras and markers: requests[security]>=2.0; python_version>="3.8"
        pkg = re.split(r"[>=<!;\[]", line)[0].strip()
        ver_match = re.search(r"==([^\s;,]+)", line)
        ver = ver_match.group(1) if ver_match else None
        if pkg:
            deps.append(Dep(name=pkg, version=ver, ecosystem="pypi"))
    return deps


def _parse_pyproject_toml(path: Path) -> list[Dep]:
    """Very simple TOML parser — handles [project].dependencies only."""
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return []

    data = tomllib.loads(path.read_text(encoding="utf-8"))
    raw = (
        data.get("project", {}).get("dependencies", [])
        + list(data.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys())
    )
    deps = []
    for spec in raw:
        if isinstance(spec, str):
            pkg = re.split(r"[>=<!;\[]", spec)[0].strip()
            ver_match = re.search(r"==([^\s;,]+)", spec)
            if pkg and pkg not in ("python",):
                deps.append(Dep(name=pkg, version=ver_match.group(1) if ver_match else None, ecosystem="pypi"))
    return deps


# ── Node ────────────────────────────────────────────────────────────────────

def _parse_package_json(path: Path) -> list[Dep]:
    data = json.loads(path.read_text(encoding="utf-8"))
    deps = []
    for section in ("dependencies", "devDependencies"):
        for name, ver_spec in data.get(section, {}).items():
            # Strip range markers: ^1.2.3 → 1.2.3
            ver = re.sub(r"^[\^~>=<]", "", ver_spec).strip()
            deps.append(Dep(name=name, version=ver or None, ecosystem="npm"))
    return deps


# ── Rust ────────────────────────────────────────────────────────────────────

def _parse_cargo_toml(path: Path) -> list[Dep]:
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return []

    data = tomllib.loads(path.read_text(encoding="utf-8"))
    deps = []
    for section in ("dependencies", "dev-dependencies"):
        for name, spec in data.get(section, {}).items():
            if isinstance(spec, str):
                ver = re.sub(r"^[^0-9]*", "", spec).strip() or None
            elif isinstance(spec, dict):
                ver_raw = spec.get("version", "")
                ver = re.sub(r"^[^0-9]*", "", ver_raw).strip() or None
            else:
                ver = None
            deps.append(Dep(name=name, version=ver, ecosystem="cargo"))
    return deps


# ── Dispatcher ──────────────────────────────────────────────────────────────

_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "requirements-dev.txt": _parse_requirements_txt,
    "requirements-test.txt": _parse_requirements_txt,
    "pyproject.toml": _parse_pyproject_toml,
    "package.json": _parse_package_json,
    "Cargo.toml": _parse_cargo_toml,
}


def parse(path: Path) -> list[Dep]:
    """Parse a dependency file and return a list of Dep objects."""
    fn = _PARSERS.get(path.name)
    if fn is None:
        raise ValueError(f"Unsupported file: {path.name}")
    return fn(path)


def auto_find(root: Path) -> list[Path]:
    """Find all supported dependency files under root (non-recursive into node_modules/.venv)."""
    found = []
    skip = {"node_modules", ".venv", "venv", ".git", "__pycache__"}
    for p in root.rglob("*"):
        if any(part in skip for part in p.parts):
            continue
        if p.name in _PARSERS:
            found.append(p)
    return found
