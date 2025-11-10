from pathlib import Path

from scanner.scanner_core import ScanConfig, scan


def test_scan_examples_benign_samples():
    sample_dir = Path(__file__).resolve().parent.parent / "examples" / "benign_samples"
    results = scan(sample_dir, ScanConfig(max_file_size=5_000_000, threads=2))
    assert results
    for result in results:
        assert result.severity in {"Safe", "Caution"}
        assert result.score < 50
