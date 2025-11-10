from scanner import heuristics


def test_calculate_score_with_multiple_findings():
    findings = [
        {"code": "exe_in_zip"},
        {"code": "pdf_token"},
        {"code": "url"},
    ]
    score, label, reasons = heuristics.calculate_score(findings)
    assert score >= 60
    assert label in {"Suspicious", "High"}
    assert any("exe_in_zip" in reason for reason in reasons)


def test_calculate_score_safe_when_empty():
    score, label, reasons = heuristics.calculate_score([])
    assert score == 0
    assert label == "Safe"
    assert reasons == []
