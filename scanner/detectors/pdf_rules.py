from typing import BinaryIO, Dict, List
import re


def analyze_pdf(f: BinaryIO, strict: bool = False) -> List[Dict]:
    data = f.read()
    findings: List[Dict] = []
    if b"/OpenAction" in data or b"/AA" in data:
        findings.append(
            {
                "rule": "pdf_auto_actions",
                "severity": "high",
                "detail": "Document defines automatic actions (OpenAction/AA).",
            }
        )
    if b"/JavaScript" in data or b"/JS" in data:
        findings.append(
            {
                "rule": "pdf_javascript",
                "severity": "high",
                "detail": "Embedded JavaScript detected.",
            }
        )
    if re.search(rb"/EmbeddedFile|/Filespec", data):
        findings.append(
            {
                "rule": "pdf_embedded_files",
                "severity": "medium",
                "detail": "Contains embedded files/attachments.",
            }
        )
    if strict and re.search(rb"http(s)?://", data):
        findings.append(
            {
                "rule": "pdf_external_links",
                "severity": "low",
                "detail": "External URLs present (strict mode).",
            }
        )
    return findings
