"""Reporters for Teacher-Safe Local File Scanner."""
from __future__ import annotations

import html
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, TextIO

LOGGER = logging.getLogger(__name__)

THEME_PATH = Path(__file__).resolve().parent / "reporting" / "html_theme.css"
_FILE_SEVERITY_CLASS = {
    "High": "badge-high",
    "Suspicious": "badge-medium",
    "Caution": "badge-medium",
    "Safe": "badge-low",
}


def write_json_report(results: List[dict], destination: Path) -> None:
    """Write *results* to *destination* in JSON format."""
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "files": results,
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def render_console_table(results: List[dict]) -> str:
    """Return a simple console table summarising scan results."""
    headers = ("Path", "Severity", "Score", "Issues")
    rows: List[tuple[str, str, str, str]] = []
    for entry in results:
        issues = ", ".join(f.get("code", "") for f in entry.get("issues", [])) or "-"
        rows.append(
            (
                entry.get("path", ""),
                entry.get("severity", ""),
                str(entry.get("score", "")),
                issues,
            )
        )
    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, column in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(column))

    def format_row(row: Iterable[str]) -> str:
        return " | ".join(col.ljust(col_widths[idx]) for idx, col in enumerate(row))

    lines = [format_row(headers), "-+-".join("-" * width for width in col_widths)]
    lines.extend(format_row(row) for row in rows)
    return "\n".join(lines)


def print_console_report(results: List[dict], stream: TextIO) -> None:
    """Print the console table to *stream*."""
    stream.write(render_console_table(results) + "\n")


def _load_theme() -> str:
    try:
        return THEME_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:  # pragma: no cover - packaging guard
        LOGGER.debug("Theme CSS missing at %s", THEME_PATH)
        return ""


def _issue_badge(severity: str | None) -> str:
    cls = f"badge-{(severity or 'low').lower()}"
    label = (severity or "low").title()
    return f'<span class="{cls}">{html.escape(label)}</span>'


def generate_html_report(results: List[dict]) -> str:
    """Generate a standalone HTML report for *results*."""
    css = _load_theme()
    summary_rows: List[str] = []
    sections: List[str] = []
    for index, entry in enumerate(results, start=1):
        path = entry.get("path", "")
        severity = entry.get("severity", "Safe")
        badge_class = _FILE_SEVERITY_CLASS.get(severity, "badge-low")
        score = entry.get("score", 0)
        summary_rows.append(
            "<tr class=\"summary-row\" data-target=\"file-{idx}\"><td><code>{path}</code></td><td><span class=\"{cls}\">{sev}</span></td><td>{score}</td></tr>".format(
                idx=index,
                path=html.escape(str(path)),
                cls=badge_class,
                sev=html.escape(severity),
                score=html.escape(str(score)),
            )
        )
        issue_items: List[str] = []
        issues = entry.get("issues", []) or []
        for issue in issues:
            code = html.escape(str(issue.get("code", "finding")))
            detail = html.escape(str(issue.get("description", "")))
            evidence = issue.get("evidence")
            badge = _issue_badge(issue.get("severity"))
            body = f"{badge} <strong>{code}</strong> — {detail}"
            if evidence:
                body += f" <code>{html.escape(str(evidence))}</code>"
            issue_items.append(f"<li>{body}</li>")
        if not issue_items:
            issue_items.append("<li>No issues detected.</li>")
        details_block = """
<details class=\"details\" open>
  <summary>Evidence ({count})</summary>
  <ul>
    {items}
  </ul>
</details>
""".format(count=len(issue_items), items="\n    ".join(issue_items))
        next_steps = """
<div class=\"next-steps\">
  <h3>What to do next</h3>
  <p>Stay cautious. Do not open this file directly on a classroom computer. If the severity is High or Suspicious, share the report with your IT helpdesk.</p>
  <p>You can quarantine the file by running the command copied below.</p>
  <button data-path=\"{path}\">Quarantine this file</button>
  <p class=\"small\">Command copied to clipboard when you press the button.</p>
</div>
""".format(path=html.escape(str(path)))
        sections.append(
            """
<section id=\"file-{idx}\">
  <h2><code>{path}</code> <span class=\"{badge}\">{severity}</span></h2>
  <p>Score: {score}</p>
  {details}
  {next_steps}
</section>
""".format(
                idx=index,
                path=html.escape(str(path)),
                badge=badge_class,
                severity=html.escape(severity),
                score=html.escape(str(score)),
                details=details_block,
                next_steps=next_steps,
            )
        )
    summary_html = "\n".join(summary_rows)
    sections_html = "\n".join(sections)
    script = """
<script>
  document.querySelectorAll('.summary-row').forEach(function(row) {
    row.addEventListener('click', function() {
      const target = document.getElementById(row.dataset.target);
      if (target) {
        target.scrollIntoView({behavior: 'smooth'});
      }
    });
  });
  document.querySelectorAll('button[data-path]').forEach(function(button) {
    button.addEventListener('click', function() {
      const filePath = button.getAttribute('data-path');
      const command = `python -m scanner quarantine "${filePath}" --dest ./quarantine`;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(command).then(function() {
          alert('Quarantine command copied to clipboard. Paste it in a terminal to run.');
        }, function() {
          window.prompt('Copy this command to quarantine the file:', command);
        });
      } else {
        window.prompt('Copy this command to quarantine the file:', command);
      }
    });
  });
</script>
"""
    return """
<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>Teacher-Safe Scanner Report</title>
<style>
{css}
body {{ font-family: Arial, sans-serif; margin: 1.5rem; }}
header {{ background: #f7f7f7; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }}
th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
th {{ background-color: #f0f0f0; }}
section {{ border: 1px solid #e0e0e0; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; }}
button {{ padding: 0.5rem 1rem; border-radius: 4px; border: 1px solid #666; background: #f5f5f5; cursor: pointer; }}
button:hover {{ background: #e0e0e0; }}
.small {{ font-size: 0.85rem; color: #555; }}
</style>
</head>
<body>
<header>
  <h1>Teacher-Safe Local File Scanner</h1>
  <p>This report is generated for defensive and educational purposes. If any file is flagged, do not open it on a production machine.</p>
  <p>Consult your IT department or open it in an isolated, school-approved sandbox.</p>
</header>
<table>
  <thead><tr><th>Path</th><th>Severity</th><th>Score</th></tr></thead>
  <tbody>
    {summary}
  </tbody>
</table>
{sections}
{script}
</body>
</html>
""".format(summary=summary_html, sections=sections_html, css=css, script=script)


def write_html_report(results: List[dict], destination: Path) -> None:
    """Write a standalone HTML report to *destination*."""
    destination.write_text(generate_html_report(results), encoding="utf-8")
