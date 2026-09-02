"""End-to-end scanning behaviour and its safety defaults."""
from __future__ import annotations

import os

import pytest

from scanner.findings import Verdict
from scanner.limits import DEFAULT_LIMITS, ScanLimits
from scanner.scanner_core import ScanConfig, iter_targets, scan, scan_file
from tests._platform import requires_posix_ids, requires_symlinks
from tests.samples import HARMLESS, make_docx, make_zip


@pytest.fixture()
def config() -> ScanConfig:
    return ScanConfig(limits=DEFAULT_LIMITS, threads=2)


def test_scan_folder_sorts_worst_first(corpus, config):
    results = scan(corpus, config)
    assert len(results) == 6
    assert results[0].verdict is Verdict.DO_NOT_OPEN
    assert results[-1].verdict is Verdict.LIKELY_SAFE


def test_clean_files_are_clean(corpus, config):
    by_name = {r.path.name: r for r in scan(corpus, config)}
    for name in ("clean_essay.txt", "clean_report.docx", "clean_photo.png"):
        assert by_name[name].verdict is Verdict.LIKELY_SAFE, name
        assert by_name[name].findings == []


def test_flagged_files_are_flagged(corpus, config):
    by_name = {r.path.name: r for r in scan(corpus, config)}
    for name in ("macro.docm", "traversal.zip", "Assignment.pdf.exe"):
        assert by_name[name].verdict is Verdict.DO_NOT_OPEN, name


def test_oversized_file_is_not_reported_as_safe(tmp_path, config):
    """Regression: the original returned severity 'Safe' for skipped files."""
    big = tmp_path / "huge.bin"
    big.write_bytes(b"x" * 4096)
    tiny = ScanConfig(limits=ScanLimits(**{**DEFAULT_LIMITS.__dict__, "max_file_size": 100}))
    result = scan_file(big, tiny)
    assert result.verdict is Verdict.COULD_NOT_INSPECT
    assert "file_too_large" in {f.code for f in result.findings}


@requires_posix_ids
def test_unreadable_file_is_not_reported_as_safe(tmp_path, config):
    target = tmp_path / "locked.bin"
    target.write_bytes(b"data")
    target.chmod(0o000)
    try:
        result = scan_file(target, config)
    finally:
        target.chmod(0o600)
    if os.geteuid() == 0:
        pytest.skip("running as root: permissions are not enforced")
    assert result.verdict is Verdict.COULD_NOT_INSPECT
    assert result.error


@requires_symlinks
def test_symlinks_are_not_followed_by_default(tmp_path, config):
    real = tmp_path / "real.txt"
    real.write_text("hello")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    result = scan_file(link, config)
    assert "symlink_not_followed" in {f.code for f in result.findings}
    assert result.verdict is Verdict.COULD_NOT_INSPECT


@requires_symlinks
def test_directory_symlinks_are_not_walked(tmp_path, config):
    inner = tmp_path / "inner"
    inner.mkdir()
    (inner / "a.txt").write_text("a")
    root = tmp_path / "root"
    root.mkdir()
    (root / "b.txt").write_text("b")
    (root / "loop").symlink_to(inner, target_is_directory=True)
    names = {p.name for p in iter_targets(root)}
    assert names == {"b.txt"}


def test_empty_file_is_informational_not_dangerous(tmp_path, config):
    empty = tmp_path / "nothing.docx"
    empty.write_bytes(b"")
    result = scan_file(empty, config)
    assert result.verdict is Verdict.LIKELY_SAFE
    assert "file_empty" in {f.code for f in result.findings}


def test_detector_exception_becomes_could_not_inspect(tmp_path, config, monkeypatch):
    target = tmp_path / "boom.pdf"
    target.write_bytes(b"%PDF-1.4\n%%EOF\n")

    def explode(*_args, **_kwargs):
        raise RuntimeError("detector bug")

    monkeypatch.setattr("scanner.scanner_core.pdf_detector.analyze_pdf", explode)
    result = scan_file(target, config)
    assert result.verdict is Verdict.COULD_NOT_INSPECT
    assert "detector bug" in (result.error or "")


def test_hash_is_computed_and_stable(tmp_path, config):
    target = tmp_path / "a.txt"
    target.write_bytes(b"hello")
    first = scan_file(target, config)
    second = scan_file(target, config)
    assert first.sha256 == second.sha256
    assert first.sha256 == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )


def test_docx_is_not_run_through_the_generic_archive_detector(tmp_path, config):
    """A .docx is a ZIP; treating it as an archive flags every normal document."""
    target = tmp_path / "report.docx"
    target.write_bytes(make_docx())
    result = scan_file(target, config)
    assert result.findings == []


def test_renamed_program_is_caught_by_content_not_name(tmp_path, config):
    target = tmp_path / "holiday_photo.png"
    target.write_bytes(b"MZ\x90\x00" + HARMLESS + b"\x00" * 256)
    result = scan_file(target, config)
    codes = {f.code for f in result.findings}
    assert "content_is_executable" in codes
    assert result.verdict is Verdict.DO_NOT_OPEN


def test_progress_callback_reports_every_file(corpus, config):
    seen = []
    scan(corpus, config, progress=lambda done, total, path: seen.append((done, total)))
    assert len(seen) == 6
    assert seen[-1][0] == seen[-1][1] == 6


def test_findings_are_deduplicated(tmp_path, config):
    target = tmp_path / "many.zip"
    target.write_bytes(make_zip([("a.exe", b"MZ"), ("a.exe.bak", b"MZ")]))
    result = scan_file(target, config)
    keys = [(f.code, f.evidence) for f in result.findings]
    assert len(keys) == len(set(keys))


def test_formats_with_no_detector_are_never_reported_as_safe(tmp_path, config):
    """Regression: .rar, .7z, .tar and .rtf produced no findings at all and came
    back LIKELY SAFE — the most dangerous possible result for a format that is
    specifically where someone hides something."""
    samples = {
        "archive.rar": b"Rar!\x1a\x07\x00" + b"x" * 200,
        "archive.7z": b"7z\xbc\xaf\x27\x1c" + b"x" * 200,
        "archive.tar": b"x" * 512,
        "notes.rtf": b"{\\rtf1\\ansi hello}",
        "mail.eml": b"From: a@b.co\nSubject: hi\n\nbody",
    }
    for name, data in samples.items():
        path = tmp_path / name
        path.write_bytes(data)
        result = scan_file(path, config)
        assert result.verdict is Verdict.COULD_NOT_INSPECT, name
        assert "container_not_inspectable" in {f.code for f in result.findings}, name


def test_the_uninspectable_notice_explains_what_to_do(tmp_path, config):
    path = tmp_path / "x.7z"
    path.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"x" * 100)
    finding = next(
        f for f in scan_file(path, config).findings if f.code == "container_not_inspectable"
    )
    assert "7-Zip" in finding.plain
    assert finding.action and finding.why
    assert finding.inspection_incomplete


def test_a_zip_is_still_inspected_normally(tmp_path, config):
    path = tmp_path / "ok.zip"
    path.write_bytes(make_zip([("essay.txt", b"words")]))
    result = scan_file(path, config)
    assert result.verdict is Verdict.LIKELY_SAFE
