"""Heuristic scoring for the Teacher-Safe Local File Scanner."""
from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

WEIGHTS: Dict[str, int] = {
    "exe_in_zip": 40,
    "zip_vba_project": 35,
    "zip_double_extension": 25,
    "zip_long_name": 10,
    "zip_nul_byte": 25,
    "pdf_token": 20,
    "double_extension": 15,
    "pe_header": 50,
    "office_macro_extension": 30,
    "office_macro_container": 45,
    "image_trailing_data": 15,
    "url_suspicious": 10,
    "url": 5,
    # Rule-based detectors
    "pdf_auto_actions": 40,
    "pdf_javascript": 35,
    "pdf_embedded_files": 20,
    "pdf_external_links": 10,
    "office_vba_project": 45,
    "office_auto_actions_hint": 15,
    "zip_susp_executable": 40,
    "zip_nested_archive": 20,
    "png_appended_data": 15,
    "jpeg_appended_data": 15,
    "image_large_exif": 10,
}

SEVERITY_BANDS: List[Tuple[int, int, str]] = [
    (0, 19, "Safe"),
    (20, 49, "Caution"),
    (50, 79, "Suspicious"),
    (80, 1000, "High"),
]


def calculate_score(findings: Iterable[Dict[str, str]]) -> tuple[int, str, list[str]]:
    """Calculate a heuristic score from individual findings."""
    score = 0
    reasons: list[str] = []
    for finding in findings:
        code = finding.get("code") or finding.get("rule", "")
        weight = WEIGHTS.get(code or "", 5)
        code = finding.get("code", "")
        weight = WEIGHTS.get(code, 5)
        score += weight
        reasons.append(f"{code}: +{weight}")
    score = min(score, 100)
    for low, high, label in SEVERITY_BANDS:
        if low <= score <= high:
            return score, label, reasons
    return score, "Unknown", reasons
