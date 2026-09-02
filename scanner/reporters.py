"""Console, JSON and HTML reporting.

The HTML report is the product's main proof surface: it is what a teacher opens,
what gets forwarded to IT, and what appears in a screenshot. It is a single
self-contained file with no external assets, no JavaScript required to read it,
and no network requests — a report about untrusted files should not itself phone
anywhere.
"""
from __future__ import annotations

import html
import json
import logging
from pathlib import Path
from typing import Dict, List, TextIO

from .findings import Finding, Severity, Verdict
from .scanner_core import ScanResult
from .triage import VERDICT_ORDER, TriageSummary

LOGGER = logging.getLogger(__name__)

_VERDICT_STYLE: Dict[Verdict, tuple[str, str, str]] = {
    #                     css class     symbol   short label
    Verdict.DO_NOT_OPEN: ("v-block", "✖", "DO NOT OPEN"),
    Verdict.REVIEW_WITH_CAUTION: ("v-caution", "!", "CAUTION"),
    Verdict.COULD_NOT_INSPECT: ("v-unknown", "?", "NOT CHECKED"),
    Verdict.LIKELY_SAFE: ("v-safe", "✓", "LIKELY SAFE"),
}

_ANSI = {
    Verdict.DO_NOT_OPEN: "\033[1;97;41m",
    Verdict.REVIEW_WITH_CAUTION: "\033[1;30;43m",
    Verdict.COULD_NOT_INSPECT: "\033[1;97;44m",
    Verdict.LIKELY_SAFE: "\033[1;30;42m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------
def write_json_report(summary: TriageSummary, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")


# --------------------------------------------------------------------------
# Console
# --------------------------------------------------------------------------
def print_console_report(
    summary: TriageSummary, stream: TextIO, *, color: bool = True, verbose: bool = False
) -> None:
    """Worst-first triage table with a plain-English headline."""
    write = stream.write

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    write("\n")
    write(paint("  " + summary.headline() + "  ", _BOLD) + "\n\n")

    tallies = [
        (Verdict.DO_NOT_OPEN, summary.blocked),
        (Verdict.REVIEW_WITH_CAUTION, summary.caution),
        (Verdict.COULD_NOT_INSPECT, summary.unchecked),
        (Verdict.LIKELY_SAFE, summary.clear),
    ]
    parts = []
    for verdict, count in tallies:
        if not count:
            continue
        _, symbol, label = _VERDICT_STYLE[verdict]
        parts.append(paint(f" {symbol} {count} {label} ", _ANSI[verdict] if color else ""))
    if parts:
        write("  " + "  ".join(parts) + "\n\n")

    interesting = [r for r in summary.results if r.verdict is not Verdict.LIKELY_SAFE]
    shown = interesting if interesting and not verbose else summary.results

    if shown:
        name_width = min(max((len(r.path.name) for r in shown), default=4), 44)
        header = f"  {'FILE'.ljust(name_width)}  {'VERDICT'.ljust(11)}  WHY"
        write(paint(header, _BOLD) + "\n")
        write("  " + "-" * (name_width + 60) + "\n")
        for result in shown:
            _, symbol, label = _VERDICT_STYLE[result.verdict]
            name = sanitize_display(result.path.name)
            if len(name) > name_width:
                name = name[: name_width - 1] + "…"
            top = result.top_finding
            reason = top.title if top else (result.error or "no indicators found")
            badge = paint(f"{symbol} {label}".ljust(11), _ANSI[result.verdict] if color else "")
            write(f"  {name.ljust(name_width)}  {badge}  {reason[:60]}\n")
        write("\n")

    if interesting and not verbose:
        write(
            paint(
                f"  {summary.clear} file(s) with no findings are not listed. "
                "Use --verbose to show everything.\n\n",
                _DIM if color else "",
            )
        )

    for result in summary.results:
        if result.verdict is Verdict.LIKELY_SAFE and not verbose:
            continue
        if not result.findings and not result.error:
            continue
        write(paint(f"  {sanitize_display(result.path)}", _BOLD) + "\n")
        for line in result.rationale:
            write(f"    {line}\n")
        for finding in sorted(
            result.findings, key=lambda f: (-f.severity.rank, -f.confidence.rank)
        ):
            if finding.severity is Severity.INFO and not verbose:
                continue
            write(
                f"    • [{finding.severity.value}/{finding.confidence.value}] "
                f"{finding.title}\n"
            )
            write(f"        {finding.plain}\n")
            if finding.evidence:
                write(f"        evidence: {sanitize_display(finding.evidence[:160])}\n")
            write(f"        what to do: {finding.action}\n")
        if result.error:
            write(f"    ! scanner error: {result.error}\n")
        write("\n")

    if summary.duplicate_groups:
        write(paint("  Identical files submitted more than once:\n", _BOLD))
        for group in summary.duplicate_groups[:5]:
            names = ", ".join(sanitize_display(Path(p).name) for p in group["paths"][:4])
            write(f"    {group['count']}x  {names}\n")
        write("\n")

    write(
        "  This scanner performs static checks only. It never opens or runs the\n"
        "  files it inspects, and it is not a replacement for antivirus.\n\n"
    )


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------
def write_html_report(summary: TriageSummary, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(generate_html_report(summary), encoding="utf-8")


#: Characters that reorder or hide text when rendered. A report about a
#: bidi-override filename must not itself be reordered by that filename — the
#: first draft of this report rendered ``invoice\u202egpj.exe`` as
#: "invoiceexe.jpg", reproducing the attack inside the evidence.
_UNSAFE_DISPLAY = {
    ord(c): f"<U+{ord(c):04X}>"
    for c in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
    "\u200b\u200c\u200d\u200e\u200f\ufeff"
}


def sanitize_display(value: object) -> str:
    """Make a name safe to *show*, replacing invisible/reordering characters."""
    text = str(value)
    text = text.translate(_UNSAFE_DISPLAY)
    return "".join(
        ch if ch.isprintable() or ch in "\t" else f"<U+{ord(ch):04X}>" for ch in text
    )


def _esc(value: object) -> str:
    return html.escape(sanitize_display(value), quote=True)


def _finding_html(finding: Finding) -> str:
    evidence = (
        f'<div class="evidence"><span>evidence</span><code>{_esc(finding.evidence)}</code></div>'
        if finding.evidence
        else ""
    )
    return f"""
      <li class="finding sev-{finding.severity.value}">
        <div class="finding-head">
          <span class="sev-pill sev-{finding.severity.value}">{_esc(finding.severity.value)}</span>
          <span class="conf">{_esc(finding.confidence.value)} confidence</span>
          <strong>{_esc(finding.title)}</strong>
        </div>
        <p class="plain">{_esc(finding.plain)}</p>
        <p class="why"><span>Why this matters</span> {_esc(finding.why)}</p>
        <p class="action"><span>What to do</span> {_esc(finding.action)}</p>
        {evidence}
        <div class="detector">detected by: {_esc(finding.detector)}</div>
      </li>"""


def _result_html(result: ScanResult, index: int) -> str:
    css, symbol, label = _VERDICT_STYLE[result.verdict]
    findings = "".join(_finding_html(f) for f in sorted(
        result.findings, key=lambda f: (-f.severity.rank, -f.confidence.rank)
    ))
    if not findings:
        findings = '<li class="finding sev-info"><p class="plain">No indicators matched.</p></li>'
    rationale = "".join(f"<li>{_esc(line)}</li>" for line in result.rationale)
    error = f'<p class="error">Scanner error: {_esc(result.error)}</p>' if result.error else ""
    return f"""
    <details class="file {css}" id="f{index}"{' open' if result.needs_attention else ''}>
      <summary>
        <span class="verdict {css}">{symbol} {_esc(label)}</span>
        <span class="fname">{_esc(result.path.name)}</span>
        <span class="fmeta">{_esc(_human(result.size))} · {_esc(result.detected_type)}
          · risk {result.risk_score}</span>
      </summary>
      <div class="file-body">
        <div class="path"><code>{_esc(result.path)}</code></div>
        {error}
        <div class="rationale"><span>How this verdict was reached</span><ul>{rationale}</ul></div>
        <ul class="findings">{findings}</ul>
        <div class="hash">SHA-256 <code>{_esc(result.sha256 or "not computed")}</code></div>
      </div>
    </details>"""


def generate_html_report(summary: TriageSummary) -> str:
    groups: Dict[Verdict, List[ScanResult]] = {v: [] for v in VERDICT_ORDER}
    for result in summary.results:
        groups[result.verdict].append(result)

    sections: List[str] = []
    counter = 0
    for verdict in VERDICT_ORDER:
        items = groups[verdict]
        if not items:
            continue
        css, symbol, label = _VERDICT_STYLE[verdict]
        body = ""
        for result in items:
            counter += 1
            body += _result_html(result, counter)
        sections.append(
            f'<section class="group {css}"><h2>{symbol} {_esc(verdict.value)} '
            f'<span class="count">{len(items)}</span></h2>{body}</section>'
        )

    tiles = "".join(
        f'<div class="tile {_VERDICT_STYLE[v][0]}"><div class="n">{n}</div>'
        f'<div class="l">{_esc(_VERDICT_STYLE[v][2])}</div></div>'
        for v, n in [
            (Verdict.DO_NOT_OPEN, summary.blocked),
            (Verdict.REVIEW_WITH_CAUTION, summary.caution),
            (Verdict.COULD_NOT_INSPECT, summary.unchecked),
            (Verdict.LIKELY_SAFE, summary.clear),
        ]
    )

    dupes = ""
    if summary.duplicate_groups:
        rows = "".join(
            "<tr><td>{count}</td><td>{names}</td>"
            "<td><code>{digest}…</code></td></tr>".format(
                count=g["count"],
                names=_esc(", ".join(Path(p).name for p in g["paths"][:6])),
                digest=_esc(g["sha256"][:16]),
            )
            for g in summary.duplicate_groups[:12]
        )
        dupes = (
            '<section class="panel"><h2>Identical files submitted more than once</h2>'
            '<table class="tbl"><thead><tr><th>Copies</th><th>Files</th><th>SHA-256</th>'
            f"</tr></thead><tbody>{rows}</tbody></table></section>"
        )

    common = ""
    if summary.top_findings:
        rows = "".join(
            '<tr><td><span class="sev-pill sev-{sev}">{sev}</span></td>'
            "<td>{title}</td><td>{files}</td></tr>".format(
                sev=_esc(f["severity"]), title=_esc(f["title"]), files=f["files"]
            )
            for f in summary.top_findings
        )
        common = (
            '<section class="panel"><h2>What was found across the batch</h2>'
            '<table class="tbl"><thead><tr><th>Severity</th><th>Finding</th><th>Files</th>'
            f"</tr></thead><tbody>{rows}</tbody></table></section>"
        )

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>File triage report — {_esc(summary.generated_at)}</title>
<style>{_CSS}</style>
</head><body>
<header>
  <div class="brand">Teacher-Safe Local File Scanner
    <span>v{_esc(summary.scanner_version)}</span></div>
  <h1>{_esc(summary.headline())}</h1>
  <p class="sub">{summary.total_files} file(s), {_esc(_human(summary.total_bytes))} scanned in
     {summary.duration_ms / 1000:.1f}s · {_esc(summary.generated_at)}</p>
  <p class="sub roots">{_esc(", ".join(summary.roots))}</p>
</header>
<div class="tiles">{tiles}</div>
<div class="wrap">
{"".join(sections)}
{common}
{dupes}
</div>
<footer>
  <p><strong>What this report is.</strong> Every check here is static: files were
  read, never opened or run. Findings are indicators, not antivirus verdicts.
  &ldquo;Likely safe&rdquo; means nothing matched the checks this tool performs —
  it is not a guarantee, and it is not a substitute for endpoint protection.</p>
  <p><strong>What to do with a red result.</strong> Do not open the file. Send this
  report to your IT team along with the filename. Do not forward the file itself
  by email.</p>
  <p class="offline">This report contains no scripts and makes no network
  requests. It is safe to store and to forward.</p>
</footer>
</body></html>"""


def _human(num: int) -> str:
    value = float(num)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:,.0f} {unit}" if unit == "B" else f"{value:,.1f} {unit}"
        value /= 1024
    return f"{num} B"


_CSS = """
:root{
  --bg:#f6f7f9; --card:#fff; --ink:#16191d; --muted:#5c6672; --line:#e3e7ec;
  --block:#b3261e; --caution:#9a6700; --unknown:#0b5cad; --safe:#1a7f37;
  --block-bg:#fdeceb; --caution-bg:#fff8e6; --unknown-bg:#eaf3fc; --safe-bg:#eaf6ec;
}
@media (prefers-color-scheme: dark){
  :root{ --bg:#111418; --card:#191d23; --ink:#e8ecf1; --muted:#98a2ae; --line:#2a3138;
    --block-bg:#33191a; --caution-bg:#332a12; --unknown-bg:#132638; --safe-bg:#12291a;
    --block:#ff8b82; --caution:#e5b23c; --unknown:#71b7f7; --safe:#63c77f; }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{padding:32px 24px 20px;max-width:1080px;margin:0 auto}
.brand{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);
  font-weight:600}
.brand span{opacity:.7}
h1{font-size:26px;line-height:1.3;margin:10px 0 6px;max-width:44ch}
.sub{color:var(--muted);font-size:13px;margin:2px 0}
.roots{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;
  max-width:1080px;margin:0 auto 24px;padding:0 24px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;
  border-left-width:4px}
.tile .n{font-size:28px;font-weight:700;line-height:1}
.tile .l{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);
  margin-top:4px;font-weight:600}
.tile.v-block{border-left-color:var(--block)} .tile.v-block .n{color:var(--block)}
.tile.v-caution{border-left-color:var(--caution)} .tile.v-caution .n{color:var(--caution)}
.tile.v-unknown{border-left-color:var(--unknown)} .tile.v-unknown .n{color:var(--unknown)}
.tile.v-safe{border-left-color:var(--safe)} .tile.v-safe .n{color:var(--safe)}
.wrap{max-width:1080px;margin:0 auto;padding:0 24px 40px}
.group{margin-bottom:28px}
.group h2{font-size:14px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);
  margin:0 0 10px;display:flex;align-items:center;gap:8px}
.group h2 .count{background:var(--line);border-radius:99px;padding:1px 9px;font-size:12px;
  color:var(--ink)}
.group.v-block h2{color:var(--block)} .group.v-caution h2{color:var(--caution)}
.group.v-unknown h2{color:var(--unknown)} .group.v-safe h2{color:var(--safe)}
details.file{background:var(--card);border:1px solid var(--line);border-radius:10px;
  margin-bottom:8px;overflow:hidden;border-left-width:4px}
details.file.v-block{border-left-color:var(--block)}
details.file.v-caution{border-left-color:var(--caution)}
details.file.v-unknown{border-left-color:var(--unknown)}
details.file.v-safe{border-left-color:var(--safe)}
summary{cursor:pointer;padding:12px 16px;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
summary::-webkit-details-marker{display:none}
.verdict{font-size:11px;font-weight:700;letter-spacing:.04em;padding:3px 9px;border-radius:99px;
  white-space:nowrap}
.verdict.v-block{background:var(--block-bg);color:var(--block)}
.verdict.v-caution{background:var(--caution-bg);color:var(--caution)}
.verdict.v-unknown{background:var(--unknown-bg);color:var(--unknown)}
.verdict.v-safe{background:var(--safe-bg);color:var(--safe)}
.fname{font-weight:600;word-break:break-all;flex:1;min-width:200px}
.fmeta{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.file-body{padding:0 16px 16px;border-top:1px solid var(--line)}
.path{margin:12px 0}
.path code,.hash code{font-size:11.5px;color:var(--muted);word-break:break-all;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.rationale{background:var(--bg);border-radius:8px;padding:10px 14px;margin:10px 0}
.rationale span{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
  font-weight:600}
.rationale ul{margin:6px 0 0;padding-left:18px;font-size:13.5px}
ul.findings{list-style:none;margin:12px 0 0;padding:0}
li.finding{border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin-bottom:8px;
  border-left-width:3px}
li.finding.sev-high{border-left-color:var(--block)}
li.finding.sev-medium{border-left-color:var(--caution)}
li.finding.sev-low{border-left-color:var(--unknown)}
li.finding.sev-info{border-left-color:var(--line)}
.finding-head{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.sev-pill{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;
  padding:2px 7px;border-radius:4px}
.sev-pill.sev-high{background:var(--block-bg);color:var(--block)}
.sev-pill.sev-medium{background:var(--caution-bg);color:var(--caution)}
.sev-pill.sev-low{background:var(--unknown-bg);color:var(--unknown)}
.sev-pill.sev-info{background:var(--line);color:var(--muted)}
.conf{font-size:11px;color:var(--muted)}
.plain{margin:0 0 8px;font-size:14.5px}
.why,.action{margin:4px 0;font-size:13px;color:var(--muted)}
.why span,.action span{display:inline-block;font-size:10px;font-weight:700;text-transform:uppercase;
  letter-spacing:.05em;color:var(--ink);opacity:.7;margin-right:6px}
.evidence{margin-top:8px;background:var(--bg);border-radius:6px;padding:7px 10px}
.evidence span{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
  font-weight:700;display:block;margin-bottom:2px}
.evidence code{font-size:11.5px;word-break:break-all;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.detector{font-size:10.5px;color:var(--muted);margin-top:8px;opacity:.75}
.error{color:var(--block);font-size:13px;font-weight:600}
.panel{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;
  margin-bottom:20px}
.panel h2{font-size:14px;margin:0 0 12px;letter-spacing:.04em;text-transform:uppercase;
  color:var(--muted)}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted);padding:0 10px 6px 0;border-bottom:1px solid var(--line)}
.tbl td{padding:7px 10px 7px 0;border-bottom:1px solid var(--line);vertical-align:top}
footer{max-width:1080px;margin:0 auto;padding:24px;border-top:1px solid var(--line);
  color:var(--muted);font-size:13px}
footer p{margin:0 0 10px;max-width:78ch}
footer strong{color:var(--ink)}
.offline{font-size:12px;opacity:.8}
@media print{
  body{background:#fff} details.file{break-inside:avoid} details{open:true}
  summary{cursor:default} .tiles{page-break-after:avoid}
}
"""

__all__ = [
    "write_json_report",
    "write_html_report",
    "generate_html_report",
    "print_console_report",
    "sanitize_display",
]
