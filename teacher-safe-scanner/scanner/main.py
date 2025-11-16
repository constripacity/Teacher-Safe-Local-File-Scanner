"""Command line entry point for the Teacher-Safe Local File Scanner.

Threat model: educators receiving potentially risky student submissions.
Limitations: static analysis only, no disinfection, no guarantee of malware
absence. The tool never executes untrusted content; it only inspects files.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import List, Sequence

from . import __version__, reporters
from .quarantine import move_to_quarantine
from .scanner_core import ScanConfig, ScanResult, scan

LOGGER = logging.getLogger(__name__)


def configure_logging(verbose: bool) -> None:
    """Configure root logging based on the verbose flag."""
    level = logging.DEBUG if verbose else logging.INFO
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
    else:  # pragma: no cover - defensive branch for repeated CLI invocations
        logging.getLogger().setLevel(level)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="teacher-safe-scanner",
        description="Static defensive scanner for teachers reviewing student submissions.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan files or directories")
    scan_parser.add_argument("targets", nargs="+", help="File(s) or directory to scan")
    scan_parser.add_argument("--watch", type=Path, help="Enable polling watch mode on directory")
    scan_parser.add_argument(
        "--max-file-size",
        type=int,
        default=100_000_000,
        help="Skip files larger than this size in bytes",
    )
    scan_parser.add_argument(
        "--use-magic",
        action="store_true",
        help="Use python-magic for type detection",
    )
    scan_parser.add_argument(
        "--use-yara",
        action="store_true",
        help="Enable experimental YARA scanning",
    )
    scan_parser.add_argument("--threads", type=int, default=4, help="Number of worker threads")
    scan_parser.add_argument(
        "--report-json",
        "--output",
        dest="report_json",
        type=Path,
        help="Path to write JSON report",
    )
    scan_parser.add_argument(
        "--report-html",
        type=Path,
        help="Path to write an HTML report",
    )
    scan_parser.add_argument(
        "--pdf-rules",
        choices=("off", "normal", "strict"),
        default="normal",
        help="Control PDF rule sensitivity",
    )
    scan_parser.add_argument(
        "--office-rules",
        choices=("off", "normal", "strict"),
        default="normal",
        help="Control Office document rule sensitivity",
    )
    scan_parser.add_argument(
        "--zip-rules",
        choices=("off", "normal", "strict"),
        default="normal",
        help="Control archive rule sensitivity",
    )
    scan_parser.add_argument(
        "--image-rules",
        choices=("off", "normal", "strict"),
        default="normal",
        help="Control image rule sensitivity",
    )

    quarantine_parser = subparsers.add_parser("quarantine", help="Move a file into quarantine")
    quarantine_parser.add_argument("path", type=Path, help="File or directory to quarantine")
    quarantine_parser.add_argument(
        "--dest", type=Path, required=True, help="Destination directory for quarantine"
    )

    report_parser = subparsers.add_parser("report", help="Render a human-friendly report from JSON")
    report_parser.add_argument("report", type=Path, help="JSON report file from a previous scan")
    report_parser.add_argument(
        "--html", action="store_true", help="Render HTML output alongside console"
    )
    report_parser.add_argument("--output", type=Path, help="Write HTML report to this path")

    return parser.parse_args(list(argv))


def watch_loop(target: Path, config: ScanConfig, *, report_json: Path | None, report_html: Path | None) -> int:
    LOGGER.info("Starting watch mode for %s", target)
    seen: dict[Path, float] = {}
    exit_code = 0
    try:
        while True:
            current_files = list(target.rglob("*")) if target.is_dir() else [target]
            changed = [
                path
                for path in current_files
                if path.is_file() and seen.get(path) != path.stat().st_mtime
            ]
            for path in changed:
                LOGGER.info("Detected change in %s", path)
                results = scan(path, config)
                exit_code = max(exit_code, emit_results(results, report_json, report_html))
                seen[path] = path.stat().st_mtime
            time.sleep(10)
    except KeyboardInterrupt:
        LOGGER.info("Watch mode interrupted by user")
        return exit_code


def emit_results(
    results: List[ScanResult],
    report_json: Path | None,
    report_html: Path | None,
) -> int:
    if not results:
        LOGGER.info("No files scanned")
        return 0
    dict_results = [res.to_dict() for res in results]
    reporters.print_console_report(dict_results, sys.stdout)
    if report_json:
        report_json.parent.mkdir(parents=True, exist_ok=True)
        reporters.write_json_report(dict_results, report_json)
        LOGGER.info("JSON report written to %s", report_json)
    if report_html:
        report_html.parent.mkdir(parents=True, exist_ok=True)
        reporters.write_html_report(dict_results, report_html)
        LOGGER.info("HTML report written to %s", report_html)
    mapping = {"Safe": 0, "Caution": 1, "Suspicious": 1, "High": 2}
    exit_code = 0
    for result in results:
        if result.error:
            exit_code = max(exit_code, 3)
        exit_code = max(exit_code, mapping.get(result.severity, 0))
    return exit_code


def handle_scan(args: argparse.Namespace) -> int:
    targets = [Path(target) for target in args.targets]
    watch_target = args.watch
    if watch_target and len(targets) != 1:
        raise SystemExit("Watch mode requires a single target")
    if watch_target and not watch_target.exists():
        raise SystemExit(f"Watch directory {watch_target} does not exist")
    config = ScanConfig(
        max_file_size=args.max_file_size,
        use_magic=args.use_magic,
        use_yara=args.use_yara,
        threads=max(args.threads, 1),
        pdf_rules=args.pdf_rules,
        office_rules=args.office_rules,
        zip_rules=args.zip_rules,
        image_rules=args.image_rules,
    )
    if watch_target:
        return watch_loop(watch_target, config, report_json=args.report_json, report_html=args.report_html)
    all_results: List[ScanResult] = []
    for target in targets:
        if not target.exists():
            LOGGER.warning("Target %s does not exist", target)
            continue
        all_results.extend(scan(target, config))
    return emit_results(all_results, args.report_json, args.report_html)


def handle_quarantine(args: argparse.Namespace) -> int:
    path = args.path
    dest = args.dest
    if not path.exists():
        raise SystemExit(f"Path {path} does not exist")
    if path.is_dir():
        for file_path in path.iterdir():
            if file_path.is_file():
                dest_path = move_to_quarantine(file_path, dest)
                LOGGER.info("Moved %s to %s", file_path, dest_path)
        return 0
    dest_path = move_to_quarantine(path, dest)
    LOGGER.info("Moved %s to %s", path, dest_path)
    return 0


def handle_report(args: argparse.Namespace) -> int:
    data = json.loads(args.report.read_text(encoding="utf-8"))
    files = data.get("files", [])
    reporters.print_console_report(files, sys.stdout)
    if args.html:
        if not args.output:
            raise SystemExit("--output is required when using --html")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        reporters.write_html_report(files, args.output)
        LOGGER.info("HTML report written to %s", args.output)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    configure_logging(args.verbose)
    if args.command == "scan":
        return handle_scan(args)
    if args.command == "quarantine":
        return handle_quarantine(args)
    if args.command == "report":
        return handle_report(args)
    raise SystemExit(f"Unknown command {args.command}")


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
