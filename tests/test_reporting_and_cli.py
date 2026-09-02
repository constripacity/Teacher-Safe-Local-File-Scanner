"""Reporting, the triage summary, the CLI, and the GUI presentation model."""
from __future__ import annotations

import io
import json

import pytest

from scanner import __version__
from scanner import main as cli
from scanner.findings import Verdict
from scanner.gui_model import detail_for, parse_dropped_paths, rows_for, summarise_for_email
from scanner.limits import DEFAULT_LIMITS
from scanner.reporters import (
    generate_html_report,
    print_console_report,
    sanitize_display,
    write_html_report,
    write_json_report,
)
from scanner.scanner_core import ScanConfig, scan
from scanner.triage import build_summary, summary_from_dict
from tests._platform import requires_hostile_filenames


@pytest.fixture()
def summary(corpus):
    results = scan(corpus, ScanConfig(limits=DEFAULT_LIMITS, threads=2))
    return build_summary(results, roots=[corpus], scanner_version=__version__, duration_ms=42)


# ------------------------------------------------------------------ triage
def test_headline_names_the_number_of_blocked_files(summary):
    assert "should not be opened" in summary.headline()
    assert str(summary.blocked) in summary.headline()


def test_counts_add_up(summary):
    assert sum(summary.counts.values()) == summary.total_files == 6


def test_exit_code_reflects_the_worst_verdict(summary):
    assert summary.exit_code() == 2


def test_duplicate_detection(tmp_path):
    root = tmp_path / "dupes"
    root.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (root / name).write_bytes(b"identical content")
    results = scan(root, ScanConfig(limits=DEFAULT_LIMITS))
    built = build_summary(results, roots=[root], scanner_version=__version__)
    assert built.duplicate_groups
    assert built.duplicate_groups[0]["count"] == 3


def test_json_round_trip_preserves_verdicts(summary, tmp_path):
    path = tmp_path / "r.json"
    write_json_report(summary, path)
    restored = summary_from_dict(json.loads(path.read_text()))
    assert restored.counts == summary.counts
    assert [r.verdict for r in restored.results] == [r.verdict for r in summary.results]
    assert restored.headline() == summary.headline()


# -------------------------------------------------------------------- html
def test_html_report_is_self_contained(summary):
    html = generate_html_report(summary)
    assert "<script" not in html.lower()
    for scheme in ("http://", "https://", "//cdn"):
        assert scheme not in html.replace("http://schemas.openxmlformats.org", "")
    assert "src=" not in html


def test_html_report_contains_every_file_and_the_headline(summary):
    html = generate_html_report(summary)
    assert summary.headline() in html
    for result in summary.results:
        assert result.path.name in html or sanitize_display(result.path.name) in html


@requires_hostile_filenames
def test_html_escapes_hostile_names(tmp_path):
    root = tmp_path / "x"
    root.mkdir()
    # No slash: it would be a path separator, not part of the filename.
    (root / "a<script>alert(1)<x>.txt").write_bytes(b"hi")
    results = scan(root, ScanConfig(limits=DEFAULT_LIMITS))
    html = generate_html_report(build_summary(results, roots=[root], scanner_version="t"))
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;" in html


def test_bidi_names_cannot_spoof_themselves_in_the_report():
    """A report about a right-to-left-override filename must not be reordered
    by that filename."""
    assert sanitize_display("invoice‮gpj.exe") == "invoice<U+202E>gpj.exe"
    assert "‮" not in sanitize_display("invoice‮gpj.exe")


def test_write_html_creates_parent_directories(summary, tmp_path):
    target = tmp_path / "deep" / "nested" / "r.html"
    write_html_report(summary, target)
    assert target.exists()


# ----------------------------------------------------------------- console
def test_console_report_is_readable_without_colour(summary):
    stream = io.StringIO()
    print_console_report(summary, stream, color=False)
    text = stream.getvalue()
    assert "\033[" not in text
    assert "DO NOT OPEN" in text
    assert "not a replacement for antivirus" in text


def test_console_report_hides_clean_files_unless_verbose(summary):
    terse, loud = io.StringIO(), io.StringIO()
    print_console_report(summary, terse, color=False, verbose=False)
    print_console_report(summary, loud, color=False, verbose=True)
    assert "clean_essay.txt" not in terse.getvalue()
    assert "clean_essay.txt" in loud.getvalue()


# --------------------------------------------------------------- gui model
def test_gui_rows_are_worst_first_and_display_safe(summary):
    rows = rows_for(summary)
    assert rows[0].verdict is Verdict.DO_NOT_OPEN
    assert all("‮" not in row.name for row in rows)


def test_gui_detail_always_has_content(summary):
    for result in summary.results:
        view = detail_for(result)
        assert view.blocks
        assert view.verdict_label


def test_email_summary_is_plain_text(summary):
    text = summarise_for_email(summary)
    assert summary.headline() in text
    assert "no file was opened or run" in text.lower()


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("{/a/b c.txt} /d.txt", ["/a/b c.txt", "/d.txt"]),
        ("/x.txt;/y.txt", ["/x.txt", "/y.txt"]),
        ("/single.txt", ["/single.txt"]),
        ("", []),
    ],
)
def test_dropped_path_parsing(raw, expected):
    # Compare with as_posix() so the '/'-based expectations hold on Windows too,
    # where Path stringifies with backslashes.
    assert [p.as_posix() for p in parse_dropped_paths(raw)] == expected


# ---------------------------------------------------------------------- cli
def test_cli_scan_exit_codes(corpus, tmp_path, capsys):
    assert cli.main(["--color", "never", "scan", str(corpus)]) == 2
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "notes.txt").write_bytes(b"just some notes")
    assert cli.main(["--color", "never", "scan", str(clean)]) == 0


def test_cli_missing_target_is_a_usage_error(tmp_path, capsys):
    assert cli.main(["scan", str(tmp_path / "nope")]) == 4
    assert "does not exist" in capsys.readouterr().err


def test_cli_writes_both_reports(corpus, tmp_path):
    html = tmp_path / "r.html"
    js = tmp_path / "r.json"
    cli.main(
        ["--color", "never", "scan", str(corpus),
         "--report-html", str(html), "--report-json", str(js)]
    )
    assert html.exists() and js.exists()
    assert json.loads(js.read_text())["total_files"] == 6


def test_cli_report_subcommand_rerenders(corpus, tmp_path):
    js = tmp_path / "r.json"
    cli.main(["--color", "never", "scan", str(corpus), "--report-json", str(js)])
    html = tmp_path / "again.html"
    assert cli.main(["--color", "never", "report", str(js), "--html", str(html)]) == 2
    assert html.exists()


def test_cli_quarantine_roundtrip(tmp_path, capsys):
    source = tmp_path / "bad.exe"
    source.write_bytes(b"MZ")
    dest = tmp_path / "q"
    assert cli.main(["quarantine", str(source), "--dest", str(dest)]) == 0
    assert not source.exists()
    capsys.readouterr()  # discard the quarantine command's own output

    assert cli.main(["quarantine-list", "--dest", str(dest), "--json"]) == 0
    entries = json.loads(capsys.readouterr().out)
    assert len(entries) == 1

    assert cli.main(["restore", entries[0]["entry_id"][:12], "--dest", str(dest)]) == 0
    assert source.exists()


def test_cli_scan_with_quarantine_moves_only_blocked_files(corpus, tmp_path):
    dest = tmp_path / "q"
    cli.main(["--color", "never", "scan", str(corpus), "--quarantine-dir", str(dest)])
    assert not (corpus / "macro.docm").exists()
    assert (corpus / "clean_essay.txt").exists()


def test_cli_version_and_help_do_not_crash(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out
