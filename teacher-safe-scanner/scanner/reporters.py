"""Reporters for Teacher-Safe Local File Scanner."""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, TextIO

LOGGER = logging.getLogger(__name__)


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
        issues = ", ".join(f["code"] for f in entry.get("issues", [])) or "-"
        rows.append(
            (entry.get("path", ""), entry.get("severity", ""), str(entry.get("score", "")), issues)
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


def generate_html_report(results: List[dict]) -> str:
    """Generate a standalone HTML report for *results*."""
    rows_html = []
    for entry in results:
        issues = "".join(
            f"<li><strong>{issue.get('code')}</strong>: {issue.get('description')}"
            + (
                f" — <code>{issue.get('evidence')}</code>"
                if issue.get("evidence")
                else ""
            )
            + "</li>"
            for issue in entry.get("issues", [])
        ) or "<li>No issues detected.</li>"
        rows_html.append(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><ul>{}</ul></td></tr>".format(
                entry.get("path"), entry.get("severity"), entry.get("score"), issues
            )
        )
    body = "\n".join(rows_html)
    return f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>Teacher-Safe Scanner Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 1.5rem; }}
header {{ background: #f7f7f7; padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 0.5rem; text-align: left; }}
th {{ background-color: #f0f0f0; }}
.severity-High {{ color: #b00020; font-weight: bold; }}
.severity-Suspicious {{ color: #d97706; font-weight: bold; }}
.severity-Caution {{ color: #eab308; font-weight: bold; }}
.severity-Safe {{ color: #15803d; font-weight: bold; }}
</style>
</head>
<body>
<header>
<h1>Teacher-Safe Local File Scanner</h1>
<p>This report is generated for defensive and educational purposes.
If any file is flagged, do not open it.</p>
<p>Consult your IT department or open it in an isolated, school-approved sandbox.</p>
</header>
<table>
<thead><tr><th>Path</th><th>Severity</th><th>Score</th><th>Issues</th></tr></thead>
<tbody>
{body}
</tbody>
</table>
</body>
</html>
"""


def write_html_report(results: List[dict], destination: Path) -> None:
    """Write a standalone HTML report to *destination*."""
    destination.write_text(generate_html_report(results), encoding="utf-8")
