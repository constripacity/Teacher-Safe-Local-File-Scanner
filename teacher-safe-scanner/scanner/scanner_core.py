"""Core orchestration for the Teacher-Safe Local File Scanner."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from . import detectors, heuristics, utils

LOGGER = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    import yara
except ImportError:  # pragma: no cover
    yara = None


@dataclass
class ScanConfig:
    """Configuration for a scan operation."""

    max_file_size: int = 100 * 1024 * 1024
    use_magic: bool = False
    use_yara: bool = False
    threads: int = 4
    pdf_rules: str = "normal"
    office_rules: str = "normal"
    zip_rules: str = "normal"
    image_rules: str = "normal"


@dataclass
class ScanResult:
    """Result produced for each scanned file."""

    path: Path
    sha256: str
    size: int
    magic_type: str
    issues: List[Dict[str, str]]
    score: int
    severity: str
    reasons: List[str]
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "path": str(self.path),
            "sha256": self.sha256,
            "size": self.size,
            "magic_type": self.magic_type,
            "issues": self.issues,
            "score": self.score,
            "severity": self.severity,
            "reasons": self.reasons,
            **({"error": self.error} if self.error else {}),
        }


YARA_RULES = """
rule TeacherSafeSuspiciousStrings {
    strings:
        $mz = "This program cannot be run in DOS mode"
        $powershell = "powershell"
    condition:
        any of them
}
"""


def _run_yara(path: Path) -> List[Dict[str, str]]:
    if yara is None:
        return []
    try:
        rules = yara.compile(source=YARA_RULES)
        matches = rules.match(str(path))
        findings: List[Dict[str, str]] = []
        for match in matches:
            if match.strings:
                evidence = ",".join(s[2] for s in match.strings)
            else:
                evidence = match.rule
            findings.append(
                {
                    "code": f"yara_{match.rule}",
                    "description": "YARA rule matched potential suspicious content",
                    "evidence": evidence,
                }
            )
        return findings
    except Exception as exc:  # pragma: no cover - optional path
        LOGGER.warning("YARA scanning failed for %s: %s", path, exc)
        return []


def _normalize_rule_findings(rule_findings: List[Dict]) -> List[Dict[str, str]]:
    issues: List[Dict[str, str]] = []
    for finding in rule_findings:
        rule = str(finding.get("rule", "rule"))
        detail = str(finding.get("detail", ""))
        issue: Dict[str, str] = {
            "code": rule,
            "description": detail,
        }
        severity = finding.get("severity")
        if severity:
            issue["severity"] = str(severity)
        issues.append(issue)
    return issues


def _deduplicate(findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen: set[tuple[str | None, str | None, str | None]] = set()
    unique: List[Dict[str, str]] = []
    for finding in findings:
        key = (
            finding.get("code"),
            finding.get("evidence"),
            finding.get("description"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _collect_findings(path: Path, magic_type: str, config: ScanConfig) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    maybe = detectors.detect_double_extension(path)
    if maybe:
        findings.append(maybe)
    maybe = detectors.detect_pe_headers(path)
    if maybe:
        findings.append(maybe)

    suffix = path.suffix.lower()
    if magic_type == "zip" or suffix in {".zip", ".docx", ".pptx", ".xlsx"}:
        findings.extend(detectors.detect_zip_contents(path))
    if magic_type == "pdf" or suffix == ".pdf":
        findings.extend(detectors.detect_pdf_risks(path))
    if suffix in {".png", ".jpg", ".jpeg"}:
        maybe = detectors.detect_image_appended_data(path)
        if maybe:
            findings.append(maybe)
    maybe = detectors.detect_office_macro(path)
    if maybe:
        findings.append(maybe)
    findings.extend(detectors.extract_urls_and_flag(path))

    if config.pdf_rules != "off" and (magic_type == "pdf" or suffix == ".pdf"):
        try:
            with path.open("rb") as handle:
                findings.extend(
                    _normalize_rule_findings(
                        detectors.analyze_pdf(handle, strict=config.pdf_rules == "strict")
                    )
                )
        except OSError as exc:
            LOGGER.warning("Unable to run PDF rules for %s: %s", path, exc)
    if config.office_rules != "off" and suffix in {".docx", ".pptx", ".xlsx", ".docm", ".xlsm", ".pptm"}:
        try:
            with path.open("rb") as handle:
                findings.extend(
                    _normalize_rule_findings(
                        detectors.analyze_office(handle, strict=config.office_rules == "strict")
                    )
                )
        except OSError as exc:
            LOGGER.warning("Unable to run Office rules for %s: %s", path, exc)
    if config.zip_rules != "off" and (magic_type == "zip" or suffix == ".zip"):
        try:
            with path.open("rb") as handle:
                findings.extend(
                    _normalize_rule_findings(
                        detectors.analyze_zip(handle, strict=config.zip_rules == "strict")
                    )
                )
        except OSError as exc:
            LOGGER.warning("Unable to run ZIP rules for %s: %s", path, exc)
    if config.image_rules != "off" and suffix in {".png", ".jpg", ".jpeg"}:
        try:
            with path.open("rb") as handle:
                findings.extend(
                    _normalize_rule_findings(
                        detectors.analyze_image(handle, strict=config.image_rules == "strict")
                    )
                )
        except OSError as exc:
            LOGGER.warning("Unable to run image rules for %s: %s", path, exc)

    if config.use_yara:
        findings.extend(_run_yara(path))
    return _deduplicate(findings)


def _scan_file(path: Path, config: ScanConfig) -> ScanResult:
    try:
        size = path.stat().st_size
    except OSError as exc:
        return ScanResult(path, "", 0, "unknown", [], 0, "Safe", [], error=str(exc))

    if size > config.max_file_size:
        return ScanResult(
            path,
            "",
            size,
            "unknown",
            [{"code": "skipped_large", "description": "File skipped due to size"}],
            0,
            "Safe",
            ["skipped_large"],
        )

    sha256 = utils.sha256_stream(path)
    magic_type = utils.detect_magic_type(path, use_magic=config.use_magic)
    findings = _collect_findings(path, magic_type, config)
    score, severity, reasons = heuristics.calculate_score(findings)
    return ScanResult(path, sha256, size, magic_type, findings, score, severity, reasons)


def scan(root: Path, config: ScanConfig) -> List[ScanResult]:
    """Scan *root* recursively and return a list of :class:`ScanResult`."""
    targets = list(utils.iter_directory_files(root))
    results: List[ScanResult] = []
    if not targets:
        LOGGER.info("No files found for scanning in %s", root)
        return results

    with ThreadPoolExecutor(max_workers=config.threads) as executor:
        future_map = {executor.submit(_scan_file, path, config): path for path in targets}
        for future in as_completed(future_map):
            result = future.result()
            results.append(result)
    results.sort(key=lambda res: res.path)
    return results
