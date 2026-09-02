"""Pytest fixtures.

Sample builders live in :mod:`tests.samples`. Every sample is harmless: the
corpus reproduces the *structure* of a risky file using inert payloads, so the
detectors can be exercised without malware ever entering this repository.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.limits import DEFAULT_LIMITS, ScanLimits  # noqa: E402
from tests.samples import HARMLESS, make_docx, make_png, make_zip  # noqa: E402


@pytest.fixture()
def limits() -> ScanLimits:
    return DEFAULT_LIMITS


@pytest.fixture()
def corpus(tmp_path: Path) -> Path:
    """A small folder of submissions: three clean, three flagged."""
    root = tmp_path / "submissions"
    root.mkdir()
    (root / "clean_essay.txt").write_bytes(b"An essay about rivers.\n")
    (root / "clean_report.docx").write_bytes(make_docx())
    (root / "clean_photo.png").write_bytes(make_png())
    (root / "macro.docm").write_bytes(make_docx({"word/vbaProject.bin": b"\x00" * 64}))
    (root / "traversal.zip").write_bytes(make_zip([("../../escape.txt", HARMLESS)]))
    (root / "Assignment.pdf.exe").write_bytes(b"MZ" + HARMLESS)
    return root
