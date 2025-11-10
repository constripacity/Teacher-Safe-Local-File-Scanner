from pathlib import Path

from scanner.detectors.pdf_rules import analyze_pdf
from tests.utils_make_samples import make_pdf_with_js


def test_pdf_js(tmp_path: Path) -> None:
    sample = tmp_path / "sample.pdf"
    make_pdf_with_js(sample)
    with sample.open("rb") as handle:
        findings = analyze_pdf(handle, strict=True)
    rules = {finding["rule"] for finding in findings}
    assert "pdf_javascript" in rules
    assert "pdf_auto_actions" in rules
