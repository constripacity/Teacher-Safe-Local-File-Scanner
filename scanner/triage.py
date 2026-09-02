"""Folder-level triage: the answer a teacher actually needs.

The unit of work for a teacher is not one file, it is *a folder of thirty
submissions*, or the ZIP their LMS exported. The question is never "what is in
this file" — it is "which of these should I not open, and what do I tell the
student".

:class:`TriageSummary` is that answer: counts by verdict, the worst files first,
and a one-line headline that can be read at a glance or pasted into an email.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .findings import Verdict
from .scanner_core import ScanResult

#: Verdicts in the order a report should present them.
VERDICT_ORDER = [
    Verdict.DO_NOT_OPEN,
    Verdict.REVIEW_WITH_CAUTION,
    Verdict.COULD_NOT_INSPECT,
    Verdict.LIKELY_SAFE,
]


@dataclass
class TriageSummary:
    generated_at: str
    scanner_version: str
    roots: List[str]
    total_files: int
    total_bytes: int
    counts: Dict[str, int]
    duplicate_groups: List[Dict[str, Any]]
    top_findings: List[Dict[str, Any]]
    detectors_used: List[str]
    duration_ms: int = 0
    results: List[ScanResult] = field(default_factory=list)

    # -- headline ------------------------------------------------------
    @property
    def blocked(self) -> int:
        return self.counts.get(Verdict.DO_NOT_OPEN.slug, 0)

    @property
    def caution(self) -> int:
        return self.counts.get(Verdict.REVIEW_WITH_CAUTION.slug, 0)

    @property
    def unchecked(self) -> int:
        return self.counts.get(Verdict.COULD_NOT_INSPECT.slug, 0)

    @property
    def clear(self) -> int:
        return self.counts.get(Verdict.LIKELY_SAFE.slug, 0)

    @property
    def needs_attention(self) -> int:
        return self.blocked + self.caution + self.unchecked

    def headline(self) -> str:
        """One sentence, written for a human, safe to paste into an email."""
        if self.total_files == 0:
            return "No files were found to check."
        if self.blocked:
            return (
                f"{self.blocked} of {self.total_files} files should not be opened. "
                f"{self.caution} more need a closer look."
                if self.caution
                else f"{self.blocked} of {self.total_files} files should not be opened."
            )
        if self.caution:
            return (
                f"Nothing here is clearly dangerous, but {self.caution} of "
                f"{self.total_files} files are worth a closer look before you open them."
            )
        if self.unchecked:
            return (
                f"{self.clear} of {self.total_files} files look fine. "
                f"{self.unchecked} could not be fully checked — that is not the same "
                "as safe."
            )
        return (
            f"All {self.total_files} files passed the checks this scanner performs. "
            "That is reassuring, not a guarantee."
        )

    def exit_code(self) -> int:
        """0 clean · 1 caution/unchecked · 2 do-not-open · 3 scanner error."""
        if any(r.error for r in self.results):
            return 3
        if self.blocked:
            return 2
        if self.caution or self.unchecked:
            return 1
        return 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "scanner_version": self.scanner_version,
            "roots": list(self.roots),
            "headline": self.headline(),
            "total_files": self.total_files,
            "total_bytes": self.total_bytes,
            "counts": dict(self.counts),
            "duplicate_groups": list(self.duplicate_groups),
            "top_findings": list(self.top_findings),
            "detectors_used": list(self.detectors_used),
            "duration_ms": self.duration_ms,
            "files": [r.to_dict() for r in self.results],
        }


def build_summary(
    results: Sequence[ScanResult],
    *,
    roots: Sequence[Path],
    scanner_version: str,
    duration_ms: int = 0,
) -> TriageSummary:
    counts: Counter[str] = Counter()
    for result in results:
        counts[result.verdict.slug] += 1

    # Duplicate detection: identical content submitted under different names is
    # both a plagiarism signal and a "you only need to look at this once" signal.
    by_hash: Dict[str, List[ScanResult]] = defaultdict(list)
    for result in results:
        if result.sha256:
            by_hash[result.sha256].append(result)
    duplicates = [
        {
            "sha256": digest,
            "count": len(group),
            "verdict": group[0].verdict.value,
            "paths": [str(r.path) for r in group[:12]],
        }
        for digest, group in sorted(by_hash.items(), key=lambda kv: -len(kv[1]))
        if len(group) > 1
    ][:20]

    finding_counter: Counter[str] = Counter()
    finding_meta: Dict[str, Dict[str, Any]] = {}
    for result in results:
        for finding in result.findings:
            finding_counter[finding.code] += 1
            finding_meta.setdefault(
                finding.code,
                {
                    "code": finding.code,
                    "title": finding.title,
                    "plain": finding.plain,
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                },
            )
    top_findings = [
        {**finding_meta[code], "files": count}
        for code, count in finding_counter.most_common(12)
    ]

    detectors = sorted({f.detector for r in results for f in r.findings})

    return TriageSummary(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        scanner_version=scanner_version,
        roots=[str(r) for r in roots],
        total_files=len(results),
        total_bytes=sum(r.size for r in results),
        counts=dict(counts),
        duplicate_groups=duplicates,
        top_findings=top_findings,
        detectors_used=detectors,
        duration_ms=duration_ms,
        results=list(results),
    )


def summary_from_dict(data: Dict[str, Any]) -> TriageSummary:
    """Rebuild a summary from a JSON report so ``report`` can re-render it."""
    results = [ScanResult.from_dict(item) for item in data.get("files", [])]
    return TriageSummary(
        generated_at=str(data.get("generated_at", "")),
        scanner_version=str(data.get("scanner_version", "unknown")),
        roots=list(data.get("roots", [])),
        total_files=int(data.get("total_files", len(results))),
        total_bytes=int(data.get("total_bytes", 0)),
        counts=dict(data.get("counts", {})),
        duplicate_groups=list(data.get("duplicate_groups", [])),
        top_findings=list(data.get("top_findings", [])),
        detectors_used=list(data.get("detectors_used", [])),
        duration_ms=int(data.get("duration_ms", 0)),
        results=results,
    )


__all__ = ["TriageSummary", "build_summary", "summary_from_dict", "VERDICT_ORDER"]
