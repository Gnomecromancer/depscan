# pkgscan

Scan `requirements.txt`, `package.json`, and `Cargo.toml` for outdated packages and known CVEs — no API keys required.

Uses [OSV](https://osv.dev/) for vulnerability data and PyPI/npm/crates.io for latest version checks.

## Install

```bash
pip install pkgscan
```

## Usage

```bash
# Scan a single file
pkgscan requirements.txt

# Auto-discover all dependency files under a directory
pkgscan --dir .

# Skip CVE checks (faster)
pkgscan requirements.txt --skip-vulns

# Only show outdated packages
pkgscan --dir . --only-outdated

# Only show packages with known CVEs
pkgscan --dir . --only-vulns
```

## Example output

```
requirements.txt  (12 packages)
────────────────────────────────────────────────────────────────────────
  requests        2.28.0           → 2.31.0  [CVE-2023-32681]
  flask           2.2.5            → 3.0.0
  click           8.1.3            8.1.7     ✓ up to date

  Summary: 2 outdated, 1 vulnerable
```

Exit code is `0` when all packages are up-to-date and vulnerability-free, `1` otherwise — handy for CI.

## Supported files

| File | Ecosystem |
|------|-----------|
| `requirements.txt` / `requirements-*.txt` | PyPI |
| `pyproject.toml` | PyPI |
| `package.json` | npm |
| `Cargo.toml` | crates.io |

## CI integration

```yaml
- name: Scan dependencies
  run: pkgscan --dir . --skip-vulns
```

## License

MIT
