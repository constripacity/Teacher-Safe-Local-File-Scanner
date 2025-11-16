from pathlib import Path

from scanner.detectors.image_rules import analyze_image
from tests.utils_make_samples import make_png_with_appended


def test_png_appended_data(tmp_path: Path) -> None:
    sample = tmp_path / "sample.png"
    make_png_with_appended(sample)
    with sample.open("rb") as handle:
        findings = analyze_image(handle, strict=False)
    rules = {finding["rule"] for finding in findings}
    assert "png_appended_data" in rules
