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
        code = finding.get("code", "")
        weight = WEIGHTS.get(code, 5)
        score += weight
        reasons.append(f"{code}: +{weight}")
    score = min(score, 100)
    for low, high, label in SEVERITY_BANDS:
        if low <= score <= high:
            return score, label, reasons
    return score, "Unknown", reasons
