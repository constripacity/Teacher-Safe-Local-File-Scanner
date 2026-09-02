"""Presentation model for the desktop window.

The window itself is a thin Tkinter shell (:mod:`scanner.gui`). Everything that
decides *what* to show lives here, with no Tk import, so it can be unit tested on
a machine with no display — which is exactly the situation in CI and in this
project's development environment.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

from .findings import Verdict
from .reporters import sanitize_display
from .scanner_core import ScanResult
from .triage import TriageSummary

#: Colour per verdict: (foreground, background). Chosen for contrast on the
#: light system background Tk gives us on all three platforms.
VERDICT_COLORS = {
    Verdict.DO_NOT_OPEN: ("#7d1a14", "#fdeceb"),
    Verdict.REVIEW_WITH_CAUTION: ("#6b4700", "#fff8e6"),
    Verdict.COULD_NOT_INSPECT: ("#0b3f78", "#eaf3fc"),
    Verdict.LIKELY_SAFE: ("#12571f", "#eaf6ec"),
}

VERDICT_SYMBOL = {
    Verdict.DO_NOT_OPEN: "✖",
    Verdict.REVIEW_WITH_CAUTION: "!",
    Verdict.COULD_NOT_INSPECT: "?",
    Verdict.LIKELY_SAFE: "✓",
}

VERDICT_SHORT = {
    Verdict.DO_NOT_OPEN: "DO NOT OPEN",
    Verdict.REVIEW_WITH_CAUTION: "CAUTION",
    Verdict.COULD_NOT_INSPECT: "NOT CHECKED",
    Verdict.LIKELY_SAFE: "LIKELY SAFE",
}


@dataclass(frozen=True)
class RowView:
    """One line in the results table."""

    verdict: Verdict
    symbol: str
    label: str
    name: str
    reason: str
    path: str
    risk: int

    @property
    def colors(self) -> tuple[str, str]:
        return VERDICT_COLORS[self.verdict]


@dataclass(frozen=True)
class DetailView:
    """The panel shown when a row is selected."""

    title: str
    verdict_label: str
    path: str
    sha256: str
    rationale: List[str]
    blocks: List[str]


def rows_for(summary: TriageSummary) -> List[RowView]:
    """Worst-first table rows, with display-safe names."""
    rows: List[RowView] = []
    for result in summary.results:
        top = result.top_finding
        reason = top.title if top else (result.error or "No indicators found")
        rows.append(
            RowView(
                verdict=result.verdict,
                symbol=VERDICT_SYMBOL[result.verdict],
                label=VERDICT_SHORT[result.verdict],
                name=sanitize_display(result.path.name),
                reason=reason,
                path=sanitize_display(result.path),
                risk=result.risk_score,
            )
        )
    return rows


def detail_for(result: ScanResult) -> DetailView:
    """Everything the detail pane shows for one file, already formatted."""
    blocks: List[str] = []
    for finding in sorted(
        result.findings, key=lambda f: (-f.severity.rank, -f.confidence.rank)
    ):
        lines = [
            f"[{finding.severity.value.upper()} · {finding.confidence.value} confidence]  "
            f"{finding.title}",
            "",
            finding.plain,
            "",
            f"Why this matters:  {finding.why}",
            f"What to do:        {finding.action}",
        ]
        if finding.evidence:
            lines.append(f"Evidence:          {sanitize_display(finding.evidence)}")
        lines.append(f"Detected by:       {finding.detector}")
        blocks.append("\n".join(lines))

    if not blocks:
        blocks.append(
            "No indicators matched.\n\n"
            "This means nothing in this file matched the checks this scanner "
            "performs. It is not a guarantee that the file is safe."
        )

    return DetailView(
        title=sanitize_display(result.path.name),
        verdict_label=f"{VERDICT_SYMBOL[result.verdict]}  {result.verdict.value}",
        path=sanitize_display(result.path),
        sha256=result.sha256 or "not computed",
        rationale=list(result.rationale),
        blocks=blocks,
    )


def status_line(summary: TriageSummary) -> str:
    return summary.headline()


def tally_line(summary: TriageSummary) -> str:
    parts = []
    for verdict, count in (
        (Verdict.DO_NOT_OPEN, summary.blocked),
        (Verdict.REVIEW_WITH_CAUTION, summary.caution),
        (Verdict.COULD_NOT_INSPECT, summary.unchecked),
        (Verdict.LIKELY_SAFE, summary.clear),
    ):
        if count:
            parts.append(f"{VERDICT_SYMBOL[verdict]} {count} {VERDICT_SHORT[verdict]}")
    return "     ".join(parts) or "Nothing scanned yet."


def parse_dropped_paths(raw: str) -> List[Path]:
    """Turn a Tk drag-and-drop / multi-select string into real paths.

    Tk hands back either a space-separated list, or ``{path with spaces}``
    groups, or a ``;``-separated list depending on platform and widget. All
    three shapes are handled here so the widget layer does not have to care.
    """
    raw = raw.strip()
    if not raw:
        return []
    paths: List[str] = []
    if "{" in raw:
        buffer = ""
        in_braces = False
        for char in raw:
            if char == "{":
                in_braces = True
                buffer = ""
            elif char == "}":
                in_braces = False
                if buffer.strip():
                    paths.append(buffer.strip())
                buffer = ""
            elif in_braces:
                buffer += char
            elif char in " \t":
                if buffer.strip():
                    paths.append(buffer.strip())
                buffer = ""
            else:
                buffer += char
        if buffer.strip():
            paths.append(buffer.strip())
    elif ";" in raw:
        paths = [p for p in raw.split(";")]
    else:
        paths = [raw]
    return [Path(p.strip()) for p in paths if p.strip()]


def summarise_for_email(summary: TriageSummary, limit: int = 20) -> str:
    """A plain-text block a teacher can paste into a message to IT."""
    lines = [summary.headline(), ""]
    flagged = [r for r in summary.results if r.verdict is not Verdict.LIKELY_SAFE]
    if not flagged:
        lines.append("No files needed attention.")
    for result in flagged[:limit]:
        top = result.top_finding
        lines.append(
            f"{VERDICT_SHORT[result.verdict]}: {sanitize_display(result.path.name)}"
            f"  —  {top.title if top else (result.error or 'see report')}"
        )
    if len(flagged) > limit:
        lines.append(f"... and {len(flagged) - limit} more (see the attached report).")
    lines += [
        "",
        f"Scanned {summary.total_files} file(s) with Teacher-Safe Local File Scanner "
        f"v{summary.scanner_version}.",
        "Static checks only — no file was opened or run. Not a replacement for antivirus.",
    ]
    return "\n".join(lines)


__all__ = [
    "RowView",
    "DetailView",
    "rows_for",
    "detail_for",
    "status_line",
    "tally_line",
    "parse_dropped_paths",
    "summarise_for_email",
    "VERDICT_COLORS",
    "VERDICT_SYMBOL",
    "VERDICT_SHORT",
]
