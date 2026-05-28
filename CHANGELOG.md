# Changelog

All notable changes to this project will be documented here.

## [0.2.0] - 2026-05-29
### Fixed
- `pyproject.toml` had a duplicate `[project]` table that made the file invalid TOML and prevented install/build. Consolidated into a single canonical block.
- `scanner/__init__.py` placed `__all__` before `from __future__ import annotations`, causing a `SyntaxError` at package import.
- `scanner/utils.py` and `scanner/scanner_core.py` each had a doubled `try: import .../except ImportError:` block left over from a botched merge, exercising dead code paths.
- `scanner/main.py` had stacked duplicate definitions of `parse_args`, `watch_loop`, `emit_results`, `handle_scan`, and `main`, plus a stray `)` that produced `SyntaxError: unmatched ')'`. Rewritten cleanly with the multi-target plural API (`targets`, `--report-json`, `--report-html`, `--pdf-rules`/`--office-rules`/`--zip-rules`/`--image-rules`).
- `scanner/reporters.py` had a duplicate `format_row` inner function, a duplicate `rows.append` block (causing `SyntaxError: '(' was never closed`), and a legacy `generate_html_report` literally nested inside the new function's return string. Tail rewritten with a single rich HTML renderer.
- `scanner/scanner_core.py` had a duplicate trailing `if config.use_yara` block where the second copy returned undeduplicated findings.
- `scanner/heuristics.py` had a doubled assignment in `calculate_score` that silently overwrote the new `code/rule` fallback with the older `code`-only lookup.
- Duplicate lines in `requirements.txt` and `requirements-optional.txt` deduplicated.

### Removed
- Orphan `teacher-safe-scanner/` subdirectory at the repository root, a stale duplicate from the v0.1 "move project to root" refactor.
- Legacy `scanner/detectors.py` (213 lines) shadowed by the `scanner/detectors/` package; the package version is the canonical implementation.

### Changed
- Project URLs in `pyproject.toml` updated from `example.com` placeholders to the real `constripacity/Teacher-Safe-Local-File-Scanner` GitHub URLs.
- Console entry point added: `teacher-safe-scan = scanner.main:main`.
- `.gitignore` expanded with standard Python/.env/.venv/IDE/OS entries.

## [0.1.0] - 2024-01-01
### Added
- Initial release of the Teacher-Safe Local File Scanner scaffold with CLI, detectors, heuristic scoring, reporters, and quarantine tooling.
- Example benign samples and example report for testing.
- GitHub Actions workflow for pytest and ruff.
