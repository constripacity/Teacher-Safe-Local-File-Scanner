"""Turn a list of findings into a verdict a teacher can act on.

The rules below are the entire severity model. They are stated in code and in
``docs/SCORING.md`` so that a school IT reviewer can disagree with them
specifically, rather than with an unexplained integer.

Rules, applied in order:

1. **Inspection completeness first.** If any finding is flagged
   ``inspection_incomplete`` the file can never be reported as safe. It becomes
   ``COULD_NOT_INSPECT`` unless something worse was also found.
2. **A single high-severity, high-or-medium-confidence finding is decisive.**
   A ``vbaProject.bin`` inside a ``.docx`` is not a matter of degree.
3. **Corroboration promotes.** Two independent medium-severity findings, or a
   high-severity finding that only reached low confidence, indicate caution.
4. **Weak signals never escalate on their own.** Any number of ``LOW``/``INFO``
   findings stays at caution at most, and a single low finding stays safe.

The numeric ``risk_score`` exists purely to sort a folder worst-first. It is
derived from the same severity/confidence matrix and is capped **per finding
code**, so an archive with 900 ``.exe`` members cannot inflate past one with
one ``.exe``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence

from .findings import Confidence, Finding, Severity, Verdict

#: Points contributed by one finding, before the per-code cap.
#: Severity picks the row, confidence scales it. Documented, not magic.
_BASE_POINTS: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 4,
    Severity.MEDIUM: 18,
    Severity.HIGH: 45,
}

_CONFIDENCE_MULTIPLIER: Dict[Confidence, float] = {
    Confidence.LOW: 0.4,
    Confidence.MEDIUM: 0.8,
    Confidence.HIGH: 1.0,
}

#: A given finding code may contribute at most this multiple of its single-hit
#: value, no matter how many times it fires.
_PER_CODE_CAP_FACTOR = 2.0


@dataclass(frozen=True)
class VerdictResult:
    verdict: Verdict
    risk_score: int
    rationale: List[str]

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "verdict_slug": self.verdict.slug,
            "risk_score": self.risk_score,
            "rationale": list(self.rationale),
        }


def finding_points(finding: Finding) -> float:
    return _BASE_POINTS[finding.severity] * _CONFIDENCE_MULTIPLIER[finding.confidence]


def risk_score(findings: Sequence[Finding]) -> int:
    """Sorting weight in 0..100, capped per finding code."""
    per_code: Dict[str, float] = {}
    caps: Dict[str, float] = {}
    for finding in findings:
        points = finding_points(finding)
        per_code[finding.code] = per_code.get(finding.code, 0.0) + points
        caps[finding.code] = max(caps.get(finding.code, 0.0), points * _PER_CODE_CAP_FACTOR)
    total = sum(min(value, caps[code]) for code, value in per_code.items())
    return int(min(round(total), 100))


def decide(findings: Iterable[Finding], *, scan_error: str | None = None) -> VerdictResult:
    """Apply the four rules above and explain which one fired."""
    items: List[Finding] = list(findings)
    rationale: List[str] = []

    incomplete = [f for f in items if f.inspection_incomplete]
    decisive = [
        f
        for f in items
        if f.severity is Severity.HIGH and f.confidence in (Confidence.HIGH, Confidence.MEDIUM)
    ]
    mediums = [f for f in items if f.severity is Severity.MEDIUM]
    weak_high = [f for f in items if f.severity is Severity.HIGH and f.confidence is Confidence.LOW]
    lows = [f for f in items if f.severity is Severity.LOW]

    score = risk_score(items)

    if decisive:
        rationale.append(
            "Rule 2: {n} high-severity finding(s) with usable confidence ({codes}).".format(
                n=len(decisive), codes=", ".join(sorted({f.code for f in decisive}))
            )
        )
        if incomplete:
            rationale.append(
                "Note: inspection was also incomplete, so there may be more than is listed."
            )
        return VerdictResult(Verdict.DO_NOT_OPEN, score, rationale)

    caution = len(mediums) >= 2 or bool(weak_high) or len(lows) >= 3 or len(mediums) == 1
    if caution:
        if len(mediums) >= 2:
            rationale.append(
                "Rule 3: {n} independent medium-severity findings corroborate each other.".format(
                    n=len(mediums)
                )
            )
        elif weak_high:
            rationale.append(
                "Rule 3: a high-severity pattern matched but only at low confidence "
                "({codes}) — worth a human look, not a firm verdict.".format(
                    codes=", ".join(sorted({f.code for f in weak_high}))
                )
            )
        elif len(mediums) == 1:
            rationale.append(
                "Rule 3: one medium-severity finding ({code}).".format(code=mediums[0].code)
            )
        else:
            rationale.append(
                "Rule 4: {n} low-severity signals accumulated; none is conclusive.".format(
                    n=len(lows)
                )
            )
        if incomplete:
            rationale.append("Inspection was incomplete; treat the result as a lower bound.")
        return VerdictResult(Verdict.REVIEW_WITH_CAUTION, score, rationale)

    if incomplete or scan_error:
        reason = scan_error or ", ".join(sorted({f.code for f in incomplete}))
        rationale.append(
            "Rule 1: the file could not be fully inspected ({reason}). "
            "Absence of findings here is not evidence of safety.".format(reason=reason)
        )
        return VerdictResult(Verdict.COULD_NOT_INSPECT, score, rationale)

    if lows:
        rationale.append(
            "Rule 4: only {n} weak signal(s) found; not enough to warrant caution.".format(
                n=len(lows)
            )
        )
    else:
        rationale.append("No risk indicators matched in the checks this scanner performs.")
    return VerdictResult(Verdict.LIKELY_SAFE, score, rationale)


__all__ = ["VerdictResult", "decide", "risk_score", "finding_points"]
