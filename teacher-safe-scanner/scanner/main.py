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
from typing import Iterable, List

from . import __version__, reporters
from .quarantine import move_to_quarantine
from .scanner_core import ScanConfig, ScanResult, scan

LOGGER = logging.getLogger(__name__)


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="teacher-safe-scanner",
        description="Static defensive scanner for teachers reviewing student submissions.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a file or directory")
    scan_parser.add_argument("target", nargs="?", default=".", help="File or directory to scan")
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
    scan_parser.add_argument("--output", type=Path, help="Path to write JSON report")

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


def watch_loop(target: Path, config: ScanConfig) -> int:
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
                exit_code = max(exit_code, emit_results(results, None))
                seen[path] = path.stat().st_mtime
            time.sleep(10)
    except KeyboardInterrupt:
        LOGGER.info("Watch mode interrupted by user")
        return exit_code


def emit_results(results: List[ScanResult], output: Path | None) -> int:
    if not results:
        LOGGER.info("No files scanned")
        return 0
    dict_results = [res.to_dict() for res in results]
    reporters.print_console_report(dict_results, sys.stdout)
    if output:
        reporters.write_json_report(dict_results, output)
        LOGGER.info("Report written to %s", output)
    mapping = {"Safe": 0, "Caution": 1, "Suspicious": 1, "High": 2}
    exit_code = 0
    for result in results:
        if result.error:
            exit_code = max(exit_code, 3)
        exit_code = max(exit_code, mapping.get(result.severity, 0))
    return exit_code


def handle_scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    watch_target = args.watch
    if watch_target and not watch_target.exists():
        raise SystemExit(f"Watch directory {watch_target} does not exist")
    config = ScanConfig(
        max_file_size=args.max_file_size,
        use_magic=args.use_magic,
        use_yara=args.use_yara,
        threads=max(args.threads, 1),
    )
    if watch_target:
        return watch_loop(watch_target, config)
    results = scan(target, config)
    return emit_results(results, args.output)


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
        reporters.write_html_report(files, args.output)
        LOGGER.info("HTML report written to %s", args.output)
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    args = parse_args(argv)
    configure_logging(args.verbose)
    if args.command == "scan":
        return handle_scan(args)
    if args.command == "quarantine":
        return handle_quarantine(args)
    if args.command == "report":
        return handle_report(args)
    raise SystemExit("Unknown command")


if __name__ == "__main__":
    sys.exit(main())
