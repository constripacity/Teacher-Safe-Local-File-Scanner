"""Command line entry point.

Threat model: a teacher or school IT assistant receives files from students and
needs to know which ones not to open. The scanner performs static analysis only:
it reads bytes, it never executes, renders, or extracts untrusted content.

Limitations are stated everywhere they matter. This is not antivirus, it has no
signature database, and "likely safe" means "nothing matched the checks this
tool performs".
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, reporters
from .findings import Verdict
from .limits import DEFAULT_LIMITS, ScanLimits
from .quarantine import QuarantineError, QuarantineStore
from .scanner_core import ScanConfig, ScanResult, scan
from .triage import build_summary, summary_from_dict

LOGGER = logging.getLogger(__name__)

EXIT_CLEAN = 0
EXIT_ATTENTION = 1
EXIT_BLOCKED = 2
EXIT_ERROR = 3
EXIT_USAGE = 4


def configure_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.WARNING)
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    root.setLevel(level)


def _use_color(flag: str) -> bool:
    if flag == "never":
        return False
    if flag == "always":
        return True
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="teacher-safe-scan",
        description=(
            "Offline static triage for student file submissions. "
            "Never opens or runs the files it inspects."
        ),
        epilog="Exit codes: 0 nothing found · 1 needs attention · 2 do not open · "
        "3 scanner error · 4 usage error",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="show every file and finding")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress warnings")
    parser.add_argument(
        "--color", choices=("auto", "always", "never"), default="auto", help="colourise output"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ---- scan ------------------------------------------------------------
    scan_p = sub.add_parser(
        "scan",
        help="scan files or folders and print a triage report",
        description="Scan a folder of submissions and report which files need attention.",
    )
    scan_p.add_argument("targets", nargs="+", type=Path, help="file(s) or folder(s) to scan")
    scan_p.add_argument(
        "--max-file-size",
        type=int,
        default=DEFAULT_LIMITS.max_file_size,
        metavar="BYTES",
        help="files larger than this are reported as NOT CHECKED (default: 100 MB)",
    )
    scan_p.add_argument("--threads", type=int, default=4, help="worker threads (default: 4)")
    scan_p.add_argument("--report-json", type=Path, metavar="PATH", help="write a JSON report")
    scan_p.add_argument(
        "--report-html", type=Path, metavar="PATH", help="write a self-contained HTML report"
    )
    scan_p.add_argument("--open-report", action="store_true", help="open the HTML report when done")
    scan_p.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="follow symbolic links (off by default: links in untrusted folders can "
        "point at device files or outside the folder)",
    )
    scan_p.add_argument(
        "--quarantine-dir",
        type=Path,
        metavar="DIR",
        help="move files at or above --quarantine-threshold into this folder",
    )
    scan_p.add_argument(
        "--quarantine-threshold",
        choices=("do_not_open", "review_with_caution"),
        default="do_not_open",
        help="which verdict triggers quarantine (default: do_not_open)",
    )
    scan_p.add_argument("--yara-rules", type=Path, metavar="PATH", help="optional YARA rules file")
    scan_p.add_argument(
        "--watch",
        action="store_true",
        help="keep watching the target folder and re-scan files as they appear",
    )
    scan_p.add_argument(
        "--watch-interval", type=float, default=2.0, help="seconds between watch polls"
    )
    for family in ("pdf", "office", "zip", "image"):
        scan_p.add_argument(
            f"--{family}-rules",
            choices=("off", "normal", "strict"),
            default="normal",
            help=f"{family} detector sensitivity",
        )

    # ---- report ----------------------------------------------------------
    report_p = sub.add_parser("report", help="re-render a saved JSON report")
    report_p.add_argument("report", type=Path, help="JSON report from a previous scan")
    report_p.add_argument("--html", type=Path, metavar="PATH", help="write HTML to this path")

    # ---- quarantine ------------------------------------------------------
    q_p = sub.add_parser("quarantine", help="move a file into quarantine (never deletes)")
    q_p.add_argument("path", type=Path, help="file to quarantine")
    q_p.add_argument("--dest", type=Path, required=True, help="quarantine folder")
    q_p.add_argument("--reason", default="manual", help="why this file was quarantined")

    list_p = sub.add_parser("quarantine-list", help="list quarantined files")
    list_p.add_argument("--dest", type=Path, required=True, help="quarantine folder")
    list_p.add_argument("--json", action="store_true", help="emit JSON")

    restore_p = sub.add_parser("restore", help="move a quarantined file back out")
    restore_p.add_argument("entry_id", help="entry id (or a unique prefix) from quarantine-list")
    restore_p.add_argument("--dest", type=Path, required=True, help="quarantine folder")
    restore_p.add_argument("--to", type=Path, help="restore here instead of the original path")
    restore_p.add_argument(
        "--force", action="store_true", help="restore even if the target exists or the hash changed"
    )

    # ---- gui / samples ---------------------------------------------------
    sub.add_parser("gui", help="launch the desktop window")
    samples_p = sub.add_parser("make-samples", help="write the benign test corpus")
    samples_p.add_argument("--out", type=Path, help="where to write the samples")

    return parser


# --------------------------------------------------------------------------
def _config_from_args(args: argparse.Namespace) -> ScanConfig:
    limits = ScanLimits(**{**DEFAULT_LIMITS.__dict__, "max_file_size": max(1, args.max_file_size)})
    return ScanConfig(
        limits=limits,
        threads=max(1, args.threads),
        follow_symlinks=args.follow_symlinks,
        use_yara=bool(args.yara_rules),
        yara_rules_path=args.yara_rules,
        pdf_rules=args.pdf_rules,
        office_rules=args.office_rules,
        zip_rules=args.zip_rules,
        image_rules=args.image_rules,
    )


def _quarantine_results(
    results: Sequence[ScanResult], directory: Path, threshold: str
) -> List[str]:
    wanted = (
        {Verdict.DO_NOT_OPEN}
        if threshold == "do_not_open"
        else {Verdict.DO_NOT_OPEN, Verdict.REVIEW_WITH_CAUTION}
    )
    store = QuarantineStore(directory)
    notes: List[str] = []
    for result in results:
        if result.verdict not in wanted:
            continue
        try:
            entry = store.quarantine(
                result.path,
                reason=(result.top_finding.code if result.top_finding else "verdict"),
                verdict=result.verdict.value,
                sha256=result.sha256 or None,
            )
        except QuarantineError as exc:
            notes.append(f"  ! could not quarantine {result.path.name}: {exc}")
        else:
            notes.append(f"  → quarantined {result.path.name} as {entry.stored_name}")
    return notes


def handle_scan(args: argparse.Namespace) -> int:
    targets = [Path(t) for t in args.targets]
    missing = [t for t in targets if not t.exists()]
    if missing:
        for target in missing:
            print(f"error: {target} does not exist", file=sys.stderr)
        return EXIT_USAGE

    config = _config_from_args(args)
    color = _use_color(args.color)

    if args.watch:
        return _watch_loop(targets, config, args, color)

    started = time.perf_counter()
    results: List[ScanResult] = []
    for target in targets:
        results.extend(scan(target, config))
    duration_ms = int((time.perf_counter() - started) * 1000)

    summary = build_summary(
        results, roots=targets, scanner_version=__version__, duration_ms=duration_ms
    )
    reporters.print_console_report(summary, sys.stdout, color=color, verbose=args.verbose)

    if args.report_json:
        reporters.write_json_report(summary, args.report_json)
        print(f"  JSON report:  {args.report_json}")
    if args.report_html:
        reporters.write_html_report(summary, args.report_html)
        print(f"  HTML report:  {args.report_html}")
        if args.open_report:
            import webbrowser

            webbrowser.open(args.report_html.resolve().as_uri())

    if args.quarantine_dir:
        notes = _quarantine_results(results, args.quarantine_dir, args.quarantine_threshold)
        if notes:
            print("\n  Quarantine:")
            print("\n".join(notes))
            print(
                f"\n  Nothing was deleted. Restore with:\n"
                f"    teacher-safe-scan restore <id> --dest {args.quarantine_dir}\n"
            )

    return summary.exit_code()


def _watch_loop(
    targets: Sequence[Path], config: ScanConfig, args: argparse.Namespace, color: bool
) -> int:
    """Re-scan only what changed.

    The original watch mode called ``rglob('*')`` over the whole tree every ten
    seconds and re-stat'ed every file. This version keeps an mtime/size index and
    scans only new or modified files, so watching a folder with thousands of
    submissions costs one directory walk per interval instead of a full re-scan.
    """
    from .scanner_core import iter_targets, scan_file

    print(f"Watching {', '.join(str(t) for t in targets)} — press Ctrl-C to stop.\n")
    seen: dict[Path, tuple[float, int]] = {}
    worst = EXIT_CLEAN
    try:
        while True:
            batch: List[ScanResult] = []
            for target in targets:
                for path in iter_targets(target, follow_symlinks=config.follow_symlinks):
                    try:
                        stat = path.stat()
                    except OSError:
                        continue
                    key = (stat.st_mtime, stat.st_size)
                    if seen.get(path) == key:
                        continue
                    seen[path] = key
                    batch.append(scan_file(path, config))
            if batch:
                batch.sort(key=lambda r: (-r.verdict.rank, -r.risk_score))
                summary = build_summary(
                    batch, roots=list(targets), scanner_version=__version__
                )
                reporters.print_console_report(
                    summary, sys.stdout, color=color, verbose=args.verbose
                )
                worst = max(worst, summary.exit_code())
            time.sleep(max(0.2, args.watch_interval))
    except KeyboardInterrupt:
        print("\nStopped watching.")
        return worst


def handle_report(args: argparse.Namespace) -> int:
    try:
        data = json.loads(args.report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not read {args.report}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    summary = summary_from_dict(data)
    reporters.print_console_report(
        summary, sys.stdout, color=_use_color(args.color), verbose=args.verbose
    )
    if args.html:
        reporters.write_html_report(summary, args.html)
        print(f"  HTML report:  {args.html}")
    return summary.exit_code()


def handle_quarantine(args: argparse.Namespace) -> int:
    try:
        entry = QuarantineStore(args.dest).quarantine(args.path, reason=args.reason)
    except QuarantineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Quarantined {args.path} as {entry.stored_name}")
    print(f"  id:      {entry.entry_id}")
    print(f"  sha256:  {entry.sha256}")
    print(f"  restore: teacher-safe-scan restore {entry.entry_id[:12]} --dest {args.dest}")
    return EXIT_CLEAN


def handle_quarantine_list(args: argparse.Namespace) -> int:
    entries = QuarantineStore(args.dest).entries()
    if args.json:
        print(json.dumps([e.__dict__ for e in entries], indent=2))
        return EXIT_CLEAN
    if not entries:
        print("Quarantine is empty.")
        return EXIT_CLEAN
    print(f"{'ID':<14} {'WHEN':<21} {'VERDICT':<22} ORIGINAL")
    for entry in entries:
        state = "  [restored]" if entry.restored_at else ""
        print(
            f"{entry.entry_id[:12]:<14} {entry.quarantined_at:<21} "
            f"{(entry.verdict or entry.reason)[:21]:<22} {entry.original_path}{state}"
        )
    return EXIT_CLEAN


def handle_restore(args: argparse.Namespace) -> int:
    try:
        target = QuarantineStore(args.dest).restore(
            args.entry_id, destination=args.to, force=args.force
        )
    except QuarantineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(f"Restored to {target}")
    return EXIT_CLEAN


def handle_gui(_args: argparse.Namespace) -> int:
    try:
        from .gui import run
    except ImportError as exc:
        print(
            "error: the desktop window needs Python's built-in tkinter, which is not "
            f"available here ({exc}).\n"
            "  Debian/Ubuntu:  sudo apt install python3-tk\n"
            "  Fedora:         sudo dnf install python3-tkinter\n"
            "  macOS/Windows:  reinstall Python from python.org (tkinter is included)\n"
            "The command line works without it:  teacher-safe-scan scan <folder>",
            file=sys.stderr,
        )
        return EXIT_ERROR
    return run()


def handle_make_samples(args: argparse.Namespace) -> int:
    try:
        from examples.generate_benign_samples import write_samples
    except ImportError:
        # Running from a source checkout that is not on sys.path.
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        try:
            from examples.generate_benign_samples import write_samples
        except ImportError as exc:  # pragma: no cover - packaging guard
            print(
                f"error: the sample generator is not available ({exc}).\n"
                "  Run it directly instead: python examples/generate_benign_samples.py",
                file=sys.stderr,
            )
            return EXIT_ERROR

    out = args.out or Path.cwd() / "benign_samples"
    written = write_samples(out)
    print(f"Wrote {len(written)} benign sample files to {out}")
    print(f"Now run:  teacher-safe-scan scan {out}")
    return EXIT_CLEAN


HANDLERS = {
    "scan": handle_scan,
    "report": handle_report,
    "quarantine": handle_quarantine,
    "quarantine-list": handle_quarantine_list,
    "restore": handle_restore,
    "gui": handle_gui,
    "make-samples": handle_make_samples,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else sys.argv[1:])
    configure_logging(args.verbose, args.quiet)
    handler = HANDLERS.get(args.command)
    if handler is None:  # pragma: no cover - argparse enforces this
        print(f"error: unknown command {args.command}", file=sys.stderr)
        return EXIT_USAGE
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
