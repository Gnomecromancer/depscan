"""CLI entry point for depscan."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import click

from .parsers import auto_find, parse
from .checkers import check


def _bold(s: str) -> str:
    return f"\033[1m{s}\033[0m"


def _red(s: str) -> str:
    return f"\033[31m{s}\033[0m"


def _yellow(s: str) -> str:
    return f"\033[33m{s}\033[0m"


def _green(s: str) -> str:
    return f"\033[32m{s}\033[0m"


def _dim(s: str) -> str:
    return f"\033[2m{s}\033[0m"


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("paths", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option(
    "--dir", "-d", "root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Scan all supported dependency files under this directory.",
)
@click.option(
    "--skip-vulns", is_flag=True, default=False,
    help="Skip vulnerability checks (faster, no OSV queries).",
)
@click.option(
    "--only-outdated", is_flag=True, default=False,
    help="Only show outdated packages.",
)
@click.option(
    "--only-vulns", is_flag=True, default=False,
    help="Only show packages with known CVEs.",
)
@click.option(
    "--no-color", is_flag=True, default=False,
    help="Disable ANSI color output.",
)
@click.option(
    "--json", "output_json", is_flag=True, default=False,
    help="Output results as JSON (machine-readable).",
)
@click.version_option(package_name="pkgscan")
def main(
    paths: tuple[Path, ...],
    root: Path | None,
    skip_vulns: bool,
    only_outdated: bool,
    only_vulns: bool,
    no_color: bool,
    output_json: bool,
) -> None:
    """Scan dependency files for outdated packages and known CVEs.

    PATHS can be individual dependency files (requirements.txt, package.json,
    Cargo.toml, pyproject.toml). Use --dir to auto-discover all supported files
    under a directory.

    \b
    Examples:
      depscan requirements.txt
      depscan --dir .
      depscan package.json --skip-vulns
    """
    if no_color or output_json:
        global _bold, _red, _yellow, _green, _dim
        _bold = _red = _yellow = _green = _dim = lambda s: s  # noqa: E731

    # Collect files
    files: list[Path] = []
    if root:
        files.extend(auto_find(root))
    for p in paths:
        p = Path(p)
        if p not in files:
            files.append(p)

    if not files:
        click.echo(
            "No dependency files found. Pass a file path or use --dir <directory>.",
            err=True,
        )
        sys.exit(1)

    total_outdated = 0
    total_vulns = 0
    total_deps = 0
    exit_code = 0
    json_output: list[dict] = []  # populated only when output_json

    for dep_file in files:
        try:
            deps = parse(dep_file)
        except ValueError as e:
            click.echo(_red(f"✗ {dep_file}: {e}"), err=True)
            continue
        except Exception as e:
            click.echo(_red(f"✗ {dep_file}: {e}"), err=True)
            continue

        if not deps:
            continue

        results = check(deps, skip_vulns=skip_vulns)
        total_deps += len(results)

        # Apply filters
        display = results
        if only_outdated:
            display = [r for r in display if r.is_outdated]
        if only_vulns:
            display = [r for r in display if r.vulns]

        file_outdated = sum(1 for r in results if r.is_outdated)
        file_vulns = sum(1 for r in results if r.vulns)
        total_outdated += file_outdated
        total_vulns += file_vulns

        if file_outdated or file_vulns:
            exit_code = 1

        if output_json:
            json_output.append({
                "file": str(dep_file),
                "packages": [
                    {
                        "name": r.dep.name,
                        "version": r.dep.version,
                        "latest": r.latest,
                        "ecosystem": r.dep.ecosystem,
                        "outdated": r.is_outdated,
                        "vulns": r.vulns,
                        "error": r.error,
                    }
                    for r in results
                ],
            })
            continue

        if not display:
            continue

        # Header
        click.echo(f"\n{_bold(str(dep_file))}  {_dim(f'({len(results)} packages)')}")
        click.echo("─" * 72)

        # Column widths
        name_w = max(len(r.dep.name) for r in display)
        name_w = max(name_w, 12)

        for r in display:
            name = r.dep.name.ljust(name_w)
            current = (r.dep.version or _dim("unpinned")).ljust(16)

            if r.error:
                status = _dim("? (lookup failed)")
            elif r.is_outdated and r.latest:
                status = _yellow(f"→ {r.latest}")
            elif r.latest:
                status = _green("✓ up to date")
            else:
                status = _dim("? (unknown)")

            vuln_str = ""
            if r.vulns:
                ids = ", ".join(r.vulns[:3])
                if len(r.vulns) > 3:
                    ids += f" (+{len(r.vulns) - 3} more)"
                vuln_str = "  " + _red(f"[{ids}]")

            click.echo(f"  {name}  {current}  {status}{vuln_str}")

        summary_parts = []
        if file_outdated:
            summary_parts.append(_yellow(f"{file_outdated} outdated"))
        if file_vulns:
            summary_parts.append(_red(f"{file_vulns} vulnerable"))
        if not file_outdated and not file_vulns:
            summary_parts.append(_green("all clear"))

        click.echo(f"\n  Summary: {', '.join(summary_parts)}")

    if output_json:
        click.echo(json.dumps({
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "files": json_output,
            "summary": {
                "total_packages": total_deps,
                "total_outdated": total_outdated,
                "total_vulnerable": total_vulns,
            },
        }, indent=2))
        sys.exit(exit_code)

    # Global summary
    if len(files) > 1:
        click.echo("\n" + "═" * 72)
        click.echo(
            f"Total: {total_deps} packages across {len(files)} files — "
            + (
                _red(f"{total_outdated} outdated, {total_vulns} vulnerable")
                if (total_outdated or total_vulns)
                else _green("all clear")
            )
        )

    sys.exit(exit_code)
