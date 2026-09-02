"""Archive detector: traversal, bombs, encryption, deception, bounded recursion."""
from __future__ import annotations

import io

import pytest

from scanner.detectors.archive import analyze_archive
from scanner.limits import ScanLimits
from tests.samples import HARMLESS, codes, encrypted_flag_zip, make_zip


def run(data: bytes, limits: ScanLimits, **kwargs):
    return analyze_archive(io.BytesIO(data), limits=limits, **kwargs)


def test_ordinary_archive_is_clean(limits):
    data = make_zip([("essay.txt", b"words"), ("notes/refs.txt", b"more")])
    assert codes(run(data, limits)) == set()


@pytest.mark.parametrize(
    "member",
    ["../../evil.txt", "/etc/passwd", "..\\..\\evil.txt", "a/../../b.txt"],
)
def test_path_traversal_is_detected(limits, member):
    assert "archive_path_traversal" in codes(run(make_zip([(member, HARMLESS)]), limits))


def test_relative_paths_that_stay_inside_are_not_flagged(limits):
    data = make_zip([("a/../b.txt", b"x"), ("./c.txt", b"y")])
    assert "archive_path_traversal" not in codes(run(data, limits))


def test_executable_member_is_high_severity(limits):
    findings = run(make_zip([("setup.exe", b"MZ")]), limits)
    match = next(f for f in findings if f.code == "archive_executable_member")
    assert match.severity.value == "high"
    assert match.action  # a teacher is told what to do
    assert match.why


def test_double_extension_member(limits):
    assert "archive_double_extension" in codes(run(make_zip([("essay.pdf.exe", b"MZ")]), limits))


def test_bidi_override_in_member_name(limits):
    assert "archive_bidi_filename" in codes(run(make_zip([("cv‮gpj.exe", b"x")]), limits))


def test_encrypted_entry_marks_inspection_incomplete(limits):
    findings = run(encrypted_flag_zip(), limits)
    match = next(f for f in findings if f.code == "archive_encrypted")
    assert match.inspection_incomplete is True


def test_compression_bomb_ratio(limits):
    data = make_zip([("zeros.bin", b"\x00" * (40 * 1024 * 1024))])
    assert "archive_bomb_ratio" in codes(run(data, limits))
    assert len(data) < 100 * 1024  # the point: tiny on disk, huge unpacked


def test_corrupt_archive_is_incomplete_not_clean(limits):
    findings = run(b"PK\x03\x04not-really-a-zip", limits)
    assert any(f.inspection_incomplete for f in findings)


def test_nested_archives_are_inspected(limits):
    inner = make_zip([("payload.exe", b"MZ")])
    outer = make_zip([("bundle.zip", inner)])
    found = codes(run(outer, limits))
    assert "archive_executable_member" in found
    assert "archive_nested" in found


def test_recursion_stops_at_the_depth_limit(limits):
    tight = ScanLimits(**{**limits.__dict__, "max_archive_depth": 1})
    deepest = make_zip([("secret.exe", b"MZ")])
    level2 = make_zip([("l2.zip", deepest)])
    level1 = make_zip([("l1.zip", level2)])
    found = codes(run(level1, tight, depth=1))
    assert "archive_depth_limit" in found


def test_office_documents_are_not_reported_as_nested_archives(limits):
    """A .docx inside a .zip is a normal submission, not 'an archive in an archive'."""
    from tests.samples import make_docx

    data = make_zip([("report.docx", make_docx())])
    assert "archive_nested" not in codes(run(data, limits))


def test_a_broken_inner_archive_does_not_condemn_the_outer_one(limits):
    data = make_zip([("inner.zip", b"not a zip at all")])
    found = codes(run(data, limits))
    assert "archive_corrupt" not in found
    assert "archive_nested_unreadable" in found


def test_member_flood_is_capped(limits):
    tight = ScanLimits(**{**limits.__dict__, "max_archive_members": 10})
    data = make_zip([(f"f{i}.txt", b"x") for i in range(50)])
    findings = run(data, tight)
    match = next(f for f in findings if f.code == "archive_member_flood")
    assert match.inspection_incomplete is True


def test_findings_are_capped_per_file(limits):
    tight = ScanLimits(**{**limits.__dict__, "max_findings_per_file": 5})
    data = make_zip([(f"prog{i}.exe", b"MZ") for i in range(100)])
    assert len(run(data, tight)) <= 5


def test_nothing_is_written_to_disk(limits, tmp_path, monkeypatch):
    """Regression guard: the detector must never extract."""
    monkeypatch.chdir(tmp_path)
    before = set(tmp_path.iterdir())
    run(make_zip([("../../escape.txt", HARMLESS), ("inner.zip", make_zip([("a", b"b")]))]), limits)
    assert set(tmp_path.iterdir()) == before
