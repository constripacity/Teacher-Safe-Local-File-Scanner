"""Finding, severity and verdict model for the Teacher-Safe Local File Scanner.

This module is the vocabulary the whole scanner speaks. It exists because the
original scoring model added opaque integers together (``exe_in_zip: 40``) and
produced a number nobody could defend. A teacher cannot act on "score 65", and a
security reviewer cannot audit it.

The model here is deliberately *explainable*:

* every :class:`Finding` carries its own evidence, a plain-English explanation,
  why it matters, and a recommended action;
* :class:`Severity` and :class:`Confidence` are separate axes, because "this file
  definitely contains a macro" and "this file might contain an appended payload"
  should not be treated alike;
* the file-level :class:`Verdict` is derived by a small set of stated rules
  (see :mod:`scanner.verdict`), not by summing magic numbers.

Nothing in this module reads or executes untrusted content.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


class Severity(enum.Enum):
    """How dangerous the thing we found would be *if the finding is correct*."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(
        cls, value: "str | Severity | None", default: "Optional[Severity]" = None
    ) -> "Severity":
        if isinstance(value, cls):
            return value
        if value is None:
            return default or cls.LOW
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return default or cls.LOW


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


class Confidence(enum.Enum):
    """How sure the detector is that the finding is real.

    ``HIGH``   the evidence is structural and unambiguous (a member named
               ``vbaProject.bin`` really is a macro store).
    ``MEDIUM`` the evidence is strong but has known benign causes.
    ``LOW``    the evidence is a weak signal that is frequently benign; useful
               as context, never as a verdict on its own.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]

    @classmethod
    def parse(
        cls, value: "str | Confidence | None", default: "Optional[Confidence]" = None
    ) -> "Confidence":
        if isinstance(value, cls):
            return value
        if value is None:
            return default or cls.MEDIUM
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return default or cls.MEDIUM


_CONFIDENCE_RANK = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


class Verdict(enum.Enum):
    """The single line a teacher actually reads.

    ``COULD_NOT_INSPECT`` is deliberately *not* a synonym for safe. The original
    scanner reported oversized and unreadable files as ``Safe``, which is the most
    dangerous possible default for a triage tool.
    """

    LIKELY_SAFE = "LIKELY SAFE TO REVIEW"
    REVIEW_WITH_CAUTION = "REVIEW WITH CAUTION"
    DO_NOT_OPEN = "DO NOT OPEN — CONTACT IT"
    COULD_NOT_INSPECT = "COULD NOT FULLY INSPECT"

    @property
    def slug(self) -> str:
        return self.name.lower()

    @property
    def rank(self) -> int:
        """Ordering for "worst first" sorting in reports."""
        return _VERDICT_RANK[self]


_VERDICT_RANK = {
    Verdict.LIKELY_SAFE: 0,
    Verdict.COULD_NOT_INSPECT: 1,
    Verdict.REVIEW_WITH_CAUTION: 2,
    Verdict.DO_NOT_OPEN: 3,
}


@dataclass(frozen=True)
class Finding:
    """One thing a detector observed, with everything needed to justify it.

    Parameters
    ----------
    code:
        Stable machine identifier, e.g. ``office_macro_present``. Used for
        deduplication, per-code contribution caps and JSON consumers.
    title:
        Short technical label for the finding.
    plain:
        The same fact stated for a non-technical reader. This is what the GUI
        and HTML report show first.
    why:
        Why this matters — the risk it implies, honestly scoped.
    action:
        What the reader should actually do about it.
    severity / confidence:
        The two independent axes described above.
    evidence:
        A concrete, quotable artefact (an archive member name, a token, an
        offset). Kept short; never raw file content beyond a snippet.
    detector:
        Which detector produced it, so a false positive can be traced home.
    inspection_incomplete:
        Set when the finding itself means "I could not finish looking" (an
        encrypted archive, a truncated read, a depth limit hit). Any such
        finding forces the verdict to at least ``COULD_NOT_INSPECT``.
    """

    code: str
    title: str
    plain: str
    why: str
    action: str
    severity: Severity = Severity.LOW
    confidence: Confidence = Confidence.MEDIUM
    evidence: Optional[str] = None
    detector: str = "unknown"
    inspection_incomplete: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    # -- serialisation -------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "code": self.code,
            "title": self.title,
            "plain": self.plain,
            "why": self.why,
            "action": self.action,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "detector": self.detector,
        }
        if self.evidence is not None:
            payload["evidence"] = self.evidence
        if self.inspection_incomplete:
            payload["inspection_incomplete"] = True
        if self.extra:
            payload["extra"] = dict(self.extra)
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Rebuild a Finding from a JSON report (used by ``scan report``)."""
        return cls(
            code=str(data.get("code", "unknown")),
            title=str(data.get("title", data.get("code", "Finding"))),
            plain=str(data.get("plain", data.get("description", ""))),
            why=str(data.get("why", "")),
            action=str(data.get("action", "")),
            severity=Severity.parse(data.get("severity"), Severity.LOW),
            confidence=Confidence.parse(data.get("confidence"), Confidence.MEDIUM),
            evidence=data.get("evidence"),
            detector=str(data.get("detector", "unknown")),
            inspection_incomplete=bool(data.get("inspection_incomplete", False)),
            extra=dict(data.get("extra") or {}),
        )

    @property
    def dedupe_key(self) -> tuple:
        return (self.code, self.evidence)


__all__ = ["Severity", "Confidence", "Verdict", "Finding"]
