"""The severity model is the product's core claim, so it is tested directly."""
from __future__ import annotations

import pytest

from scanner.findings import Confidence, Finding, Severity, Verdict
from scanner.verdict import decide, risk_score


def f(code: str, severity: Severity, confidence: Confidence, incomplete: bool = False) -> Finding:
    return Finding(
        code=code,
        title=code,
        plain="",
        why="",
        action="",
        severity=severity,
        confidence=confidence,
        inspection_incomplete=incomplete,
    )


def test_no_findings_is_likely_safe():
    assert decide([]).verdict is Verdict.LIKELY_SAFE


def test_single_high_confidence_high_severity_is_decisive():
    result = decide([f("macro", Severity.HIGH, Confidence.HIGH)])
    assert result.verdict is Verdict.DO_NOT_OPEN
    assert "Rule 2" in result.rationale[0]


def test_high_severity_at_low_confidence_only_warrants_caution():
    result = decide([f("maybe", Severity.HIGH, Confidence.LOW)])
    assert result.verdict is Verdict.REVIEW_WITH_CAUTION


def test_two_mediums_corroborate_to_caution():
    result = decide(
        [f("a", Severity.MEDIUM, Confidence.MEDIUM), f("b", Severity.MEDIUM, Confidence.MEDIUM)]
    )
    assert result.verdict is Verdict.REVIEW_WITH_CAUTION


def test_single_low_signal_stays_safe():
    assert decide([f("weak", Severity.LOW, Confidence.LOW)]).verdict is Verdict.LIKELY_SAFE


def test_many_low_signals_reach_caution_but_never_block():
    result = decide([f(f"l{i}", Severity.LOW, Confidence.MEDIUM) for i in range(9)])
    assert result.verdict is Verdict.REVIEW_WITH_CAUTION


def test_incomplete_inspection_is_never_reported_as_safe():
    """The original scanner returned 'Safe' for oversized and errored files."""
    result = decide([f("encrypted", Severity.LOW, Confidence.HIGH, incomplete=True)])
    assert result.verdict is Verdict.COULD_NOT_INSPECT
    assert "not evidence of safety" in " ".join(result.rationale)


def test_scan_error_forces_could_not_inspect():
    assert decide([], scan_error="permission denied").verdict is Verdict.COULD_NOT_INSPECT


def test_incomplete_does_not_downgrade_a_block():
    result = decide(
        [
            f("macro", Severity.HIGH, Confidence.HIGH),
            f("encrypted", Severity.LOW, Confidence.HIGH, incomplete=True),
        ]
    )
    assert result.verdict is Verdict.DO_NOT_OPEN
    assert any("incomplete" in line for line in result.rationale)


def test_repeated_identical_findings_cannot_inflate_the_score():
    """A hostile archive with 900 executables must not out-score a real threat."""
    one = risk_score([f("exe", Severity.HIGH, Confidence.HIGH)])
    many = risk_score([f("exe", Severity.HIGH, Confidence.HIGH)] * 900)
    assert many <= one * 2
    assert many < 100


def test_score_is_bounded():
    findings = [f(f"c{i}", Severity.HIGH, Confidence.HIGH) for i in range(50)]
    assert 0 <= risk_score(findings) <= 100


@pytest.mark.parametrize(
    "verdict,expected_rank",
    [
        (Verdict.LIKELY_SAFE, 0),
        (Verdict.COULD_NOT_INSPECT, 1),
        (Verdict.REVIEW_WITH_CAUTION, 2),
        (Verdict.DO_NOT_OPEN, 3),
    ],
)
def test_verdict_ordering_puts_worst_last(verdict, expected_rank):
    assert verdict.rank == expected_rank
