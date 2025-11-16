from pathlib import Path

from scanner.detectors.office_rules import analyze_office
from tests.utils_make_samples import make_office_with_vba


def test_office_vba_detection(tmp_path: Path) -> None:
    sample = tmp_path / "sample.docx"
    make_office_with_vba(sample)
    with sample.open("rb") as handle:
        findings = analyze_office(handle, strict=False)
    rules = {finding["rule"] for finding in findings}
    assert "office_vba_project" in rules
