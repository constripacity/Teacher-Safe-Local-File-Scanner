#!/usr/bin/env python3
"""Assert that every benign sample lands in the verdict it is meant to.

This is the project's detection regression test. If a detector is weakened, a
sample silently drops to LIKELY SAFE and this fails loudly. If a detector becomes
noisy, a clean sample stops being clean and this fails too — which is the failure
that actually matters, because a triage tool that cries wolf gets uninstalled.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from examples.generate_benign_samples import write_samples  # noqa: E402
from scanner.findings import Verdict  # noqa: E402
from scanner.limits import DEFAULT_LIMITS  # noqa: E402
from scanner.scanner_core import ScanConfig, scan  # noqa: E402

BLOCK = Verdict.DO_NOT_OPEN
CAUTION = Verdict.REVIEW_WITH_CAUTION
UNKNOWN = Verdict.COULD_NOT_INSPECT
SAFE = Verdict.LIKELY_SAFE

#: filename -> (expected verdict, a finding code that must be present)
EXPECTED: dict[str, tuple[Verdict, str | None]] = {
    "README.md": (SAFE, None),
    "clean_essay.txt": (SAFE, None),
    "clean_report.docx": (SAFE, None),
    "clean_diagram.png": (SAFE, None),
    "clean_photo.jpg": (SAFE, None),
    "clean_worksheet.pdf": (SAFE, None),
    "clean_homework.zip": (SAFE, None),
    "empty_submission.docx": (SAFE, "file_empty"),
    "archive_nested_deep.zip": (SAFE, "archive_nested"),
    "archive_path_traversal.zip": (BLOCK, "archive_path_traversal"),
    "archive_with_program.zip": (BLOCK, "archive_executable_member"),
    "archive_double_extension.zip": (BLOCK, "archive_double_extension"),
    "archive_zip_bomb_shape.zip": (BLOCK, "archive_bomb_ratio"),
    "office_with_macro.docm": (BLOCK, "office_macro_present"),
    "office_remote_template.docx": (BLOCK, "office_external_attachedtemplate"),
    "office_dde_field.docx": (BLOCK, "office_dde_field"),
    "office_embedded_object.docx": (CAUTION, "office_embedded_object"),
    "office_renamed_program.docx": (BLOCK, "content_is_executable"),
    "pdf_javascript.pdf": (BLOCK, "pdf_javascript"),
    "pdf_launch_action.pdf": (BLOCK, "pdf_launch_action"),
    "pdf_appended_payload.pdf": (CAUTION, "pdf_appended_data"),
    "image_polyglot.png": (BLOCK, "image_polyglot"),
    "image_large_appended.jpg": (BLOCK, "image_large_appended_data"),
    "image_is_really_a_program.jpg": (BLOCK, "content_is_executable"),
    "Assignment.pdf.exe": (BLOCK, "name_double_extension"),
    "invoice‮gpj.exe": (BLOCK, "name_bidi_override"),
    "links_suspicious.txt": (CAUTION, "url_punycode_host"),
    "archive_password_protected.zip": (CAUTION, "archive_encrypted"),
    "broken_upload.zip": (UNKNOWN, "archive_corrupt"),
    "coursework.7z": (UNKNOWN, "container_not_inspectable"),
    "essay.rtf": (UNKNOWN, "container_not_inspectable"),
}


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "samples"
        write_samples(out)
        results = scan(out, ScanConfig(limits=DEFAULT_LIMITS, threads=4))

    by_name = {r.path.name: r for r in results}
    failures: list[str] = []

    unexpected = set(by_name) - set(EXPECTED)
    if unexpected:
        failures.append(f"corpus has files with no expectation recorded: {sorted(unexpected)}")
    missing = set(EXPECTED) - set(by_name)
    if missing:
        failures.append(f"expected samples were not produced: {sorted(missing)}")

    for name, (verdict, code) in EXPECTED.items():
        result = by_name.get(name)
        if result is None:
            continue
        if result.verdict is not verdict:
            failures.append(
                f"{name}: expected {verdict.name}, got {result.verdict.name} "
                f"(findings: {sorted(f.code for f in result.findings)})"
            )
        if code and code not in {f.code for f in result.findings}:
            failures.append(
                f"{name}: expected finding {code!r}, got "
                f"{sorted(f.code for f in result.findings)}"
            )

    if failures:
        print("DETECTION REGRESSION\n")
        for line in failures:
            print(f"  ✗ {line}")
        return 1

    blocked = sum(1 for v, _ in EXPECTED.values() if v is BLOCK)
    clean = sum(1 for v, _ in EXPECTED.values() if v is SAFE)
    print(
        f"corpus OK: {len(EXPECTED)} samples — {blocked} correctly blocked, "
        f"{clean} correctly clean, no false positives."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
