from pathlib import Path

from scanner.detectors.zip_rules import analyze_zip
from tests.utils_make_samples import make_zip_with_double_ext


def test_zip_double_ext(tmp_path: Path) -> None:
    sample = tmp_path / "sample.zip"
    make_zip_with_double_ext(sample)
    with sample.open("rb") as handle:
        findings = analyze_zip(handle, strict=False)
    rules = {finding["rule"] for finding in findings}
    assert "zip_double_extension" in rules
    assert "zip_susp_executable" in rules
