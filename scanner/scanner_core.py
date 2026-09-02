"""Core orchestration: walk a target, run detectors, produce verdicts.

Design notes worth knowing before changing anything here:

* **Nothing is ever reported as safe by default.** A file that is too large, is
  a symlink, cannot be opened, or raised an exception becomes
  ``COULD_NOT_INSPECT``. The previous implementation returned ``severity="Safe"``
  for oversized and errored files, which is the most dangerous possible failure
  mode for a triage tool.
* **Every file is opened exactly once** and the handle is passed to the
  detectors, instead of each detector re-opening and re-reading the file.
* **Symlinks are not followed.** A submission containing a link to
  ``/dev/urandom`` would otherwise hang the hasher forever.
* Detectors are dispatched on *sniffed content type first*, extension second,
  so a renamed file is still analysed as what it really is.
"""
from __future__ import annotations

import hashlib
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, Iterator, List, Optional, Sequence

from . import __version__
from .detectors import archive as archive_detector
from .detectors import general as general_detector
from .detectors import image as image_detector
from .detectors import office as office_detector
from .detectors import pdf as pdf_detector
from .detectors.base import read_head, sniff_magic
from .findings import Confidence, Finding, Severity, Verdict
from .limits import DEFAULT_LIMITS, ScanLimits
from .verdict import VerdictResult, decide

LOGGER = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024

OFFICE_SUFFIXES = frozenset(
    {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt"}
)
IMAGE_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"})
TEXTISH_SUFFIXES = frozenset(
    {".txt", ".md", ".csv", ".html", ".htm", ".xml", ".json", ".log", ".srt", ""}
)

#: Container formats this scanner has no detector for.
#:
#: Reporting these as LIKELY SAFE would break the project's central promise —
#: "unchecked is never clean" — in the most dangerous way possible, because a
#: .rar or .7z is exactly where someone puts something they do not want looked
#: at. Each of these needs a third-party library to open, which is a dependency
#: this project deliberately does not have.
UNINSPECTABLE_CONTAINERS: Dict[str, str] = {
    "rar": "RAR archive",
    "7z": "7-Zip archive",
    "gzip": "gzip archive",
    "bzip2": "bzip2 archive",
    "xz": "xz archive",
    "rtf": "RTF document",
}
UNINSPECTABLE_SUFFIXES: Dict[str, str] = {
    ".rar": "RAR archive",
    ".7z": "7-Zip archive",
    ".gz": "gzip archive",
    ".tgz": "gzip archive",
    ".bz2": "bzip2 archive",
    ".xz": "xz archive",
    ".tar": "TAR archive",
    ".rtf": "RTF document",
    ".iso": "disc image",
    ".dmg": "macOS disk image",
    ".cab": "Windows cabinet archive",
    ".arj": "ARJ archive",
    ".ace": "ACE archive",
    ".lzh": "LZH archive",
    ".msg": "Outlook message",
    ".eml": "email message",
    ".one": "OneNote notebook",
}


@dataclass
class ScanConfig:
    """Everything that changes scanner behaviour, in one place."""

    limits: ScanLimits = field(default_factory=lambda: DEFAULT_LIMITS)
    threads: int = 4
    follow_symlinks: bool = False
    use_yara: bool = False
    yara_rules_path: Optional[Path] = None

    # Per-family switches kept for CLI compatibility: "off" | "normal" | "strict".
    pdf_rules: str = "normal"
    office_rules: str = "normal"
    zip_rules: str = "normal"
    image_rules: str = "normal"

    @property
    def max_file_size(self) -> int:
        return self.limits.max_file_size


@dataclass
class ScanResult:
    """One scanned file, its findings, and the verdict derived from them."""

    path: Path
    size: int
    sha256: str
    detected_type: str
    findings: List[Finding]
    verdict: Verdict
    risk_score: int
    rationale: List[str]
    error: Optional[str] = None
    duration_ms: int = 0

    # -- convenience --------------------------------------------------
    @property
    def needs_attention(self) -> bool:
        return self.verdict in (Verdict.DO_NOT_OPEN, Verdict.REVIEW_WITH_CAUTION)

    @property
    def top_finding(self) -> Optional[Finding]:
        if not self.findings:
            return None
        return max(
            self.findings,
            key=lambda f: (f.severity.rank, f.confidence.rank),
        )

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "path": str(self.path),
            "name": self.path.name,
            "size": self.size,
            "sha256": self.sha256,
            "detected_type": self.detected_type,
            "verdict": self.verdict.value,
            "verdict_slug": self.verdict.slug,
            "risk_score": self.risk_score,
            "rationale": list(self.rationale),
            "findings": [f.to_dict() for f in self.findings],
            "duration_ms": self.duration_ms,
        }
        if self.error:
            payload["error"] = self.error
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        verdict = next(
            (v for v in Verdict if v.value == data.get("verdict")),
            Verdict.COULD_NOT_INSPECT,
        )
        return cls(
            path=Path(str(data.get("path", ""))),
            size=int(data.get("size", 0)),
            sha256=str(data.get("sha256", "")),
            detected_type=str(data.get("detected_type", "unknown")),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            verdict=verdict,
            risk_score=int(data.get("risk_score", 0)),
            rationale=list(data.get("rationale", [])),
            error=data.get("error"),
            duration_ms=int(data.get("duration_ms", 0)),
        )


def _incomplete(code: str, plain: str, why: str, action: str, evidence: str) -> Finding:
    return Finding(
        code=code,
        title=plain,
        plain=plain,
        why=why,
        action=action,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        evidence=evidence,
        detector="core",
        inspection_incomplete=True,
    )


def iter_targets(root: Path, *, follow_symlinks: bool = False) -> Iterator[Path]:
    """Yield files beneath *root*, without following directory symlinks."""
    if root.is_file() or root.is_symlink():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_symlinks):
        base = Path(dirpath)
        if not follow_symlinks:
            dirnames[:] = [d for d in dirnames if not (base / d).is_symlink()]
        for filename in sorted(filenames):
            yield base / filename


def sha256_of(handle: BinaryIO) -> str:
    handle.seek(0)
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _dedupe(findings: Sequence[Finding], limit: int) -> List[Finding]:
    seen: set = set()
    out: List[Finding] = []
    for finding in findings:
        key = finding.dedupe_key
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
        if len(out) >= limit:
            break
    return out


def scan_file(path: Path, config: ScanConfig) -> ScanResult:
    """Inspect one file. Never raises; failures become COULD_NOT_INSPECT."""
    import time

    started = time.perf_counter()
    limits = config.limits

    def finish(
        findings: List[Finding],
        *,
        size: int = 0,
        sha: str = "",
        detected: str = "unknown",
        error: Optional[str] = None,
    ) -> ScanResult:
        deduped = _dedupe(findings, limits.max_findings_per_file)
        outcome: VerdictResult = decide(deduped, scan_error=error)
        return ScanResult(
            path=path,
            size=size,
            sha256=sha,
            detected_type=detected,
            findings=deduped,
            verdict=outcome.verdict,
            risk_score=outcome.risk_score,
            rationale=outcome.rationale,
            error=error,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    name_findings = general_detector.analyze_name(path)

    if path.is_symlink() and not config.follow_symlinks:
        try:
            target = os.readlink(path)
        except OSError:
            target = "?"
        return finish(
            name_findings
            + [
                _incomplete(
                    "symlink_not_followed",
                    "This entry is a shortcut to another location, not a real file.",
                    "Following links from an untrusted folder can lead the scanner "
                    "to a device file or somewhere outside the folder you meant to "
                    "check, so links are listed but not followed.",
                    "Check what the link points at before doing anything with it.",
                    f"-> {target}",
                )
            ],
            detected="symlink",
        )

    try:
        stat = path.stat()
    except OSError as exc:
        return finish(name_findings, error=f"cannot stat file: {exc}")

    if not path.is_file():
        return finish(name_findings, error="not a regular file", detected="special")

    size = stat.st_size

    if size == 0:
        return finish(
            name_findings
            + [
                Finding(
                    code="file_empty",
                    title="File is empty",
                    plain="This file contains no data at all.",
                    why="An empty submission is a failed upload, not a threat.",
                    action="Ask the student to submit it again.",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    detector="core",
                )
            ],
            size=0,
            sha=hashlib.sha256(b"").hexdigest(),
            detected="empty",
        )

    if size > limits.max_file_size:
        return finish(
            name_findings
            + [
                _incomplete(
                    "file_too_large",
                    f"This file is {size / (1024 * 1024):,.0f} MB, larger than the "
                    "scanner's limit, so it was not examined.",
                    "A file that was not examined has not been cleared. Raising "
                    "--max-file-size will scan it, at the cost of more memory.",
                    "Either raise the size limit and re-scan, or treat this file as "
                    "unchecked.",
                    f"{size} bytes > {limits.max_file_size} limit",
                )
            ],
            size=size,
            detected="unknown",
        )

    try:
        with path.open("rb") as handle:
            sha = sha256_of(handle)
            head = read_head(handle, min(limits.head_bytes, 4096))
            detected = sniff_magic(head)
            findings = list(name_findings)
            findings.extend(
                general_detector.analyze_content(handle, path, limits=limits, magic=detected)
            )
            findings.extend(
                _dispatch(handle, path, detected=detected, size=size, config=config)
            )
    except (OSError, MemoryError) as exc:
        return finish(name_findings, size=size, error=f"could not read file: {exc}")
    except Exception as exc:  # pragma: no cover - detector bug guard
        LOGGER.exception("Detector raised on %s", path)
        return finish(name_findings, size=size, error=f"scanner error: {exc!r}")

    return finish(findings, size=size, sha=sha, detected=detected)


def _dispatch(
    handle: BinaryIO, path: Path, *, detected: str, size: int, config: ScanConfig
) -> List[Finding]:
    """Route to format detectors by sniffed type first, extension second."""
    limits = config.limits
    suffix = path.suffix.lower()
    findings: List[Finding] = []

    is_ooxml_name = suffix in OFFICE_SUFFIXES
    is_zip_like = detected == "zip"

    if config.office_rules != "off" and (is_ooxml_name or detected == "ole"):
        findings.extend(office_detector.analyze_office(handle, limits=limits, suffix=suffix))

    # A .docx is a ZIP, but running the archive detector on it would flag every
    # normal document. Only run archive analysis when this is a real archive.
    if config.zip_rules != "off" and is_zip_like and not is_ooxml_name:
        findings.extend(
            archive_detector.analyze_archive(handle, limits=limits, display_name=path.name)
        )
    elif config.zip_rules != "off" and is_ooxml_name and is_zip_like:
        # Still worth checking an OOXML container for traversal and bombs, but
        # not for "contains other archives" style findings.
        findings.extend(
            f
            for f in archive_detector.analyze_archive(
                handle, limits=limits, display_name=path.name, depth=1
            )
            if f.code
            in {
                "archive_path_traversal",
                "archive_bomb_ratio",
                "archive_bomb_total",
                "archive_nul_in_name",
                "archive_bidi_filename",
                "archive_member_flood",
                "archive_encrypted",
            }
        )

    if config.pdf_rules != "off" and (detected == "pdf" or suffix == ".pdf"):
        findings.extend(pdf_detector.analyze_pdf(handle, limits=limits, size=size))

    if config.image_rules != "off" and (
        detected in {"png", "jpeg", "gif"} or suffix in IMAGE_SUFFIXES
    ):
        findings.extend(
            image_detector.analyze_image(handle, limits=limits, size=size, suffix=suffix)
        )

    # A format with no detector must say so. See UNINSPECTABLE_CONTAINERS.
    label = UNINSPECTABLE_CONTAINERS.get(detected) or UNINSPECTABLE_SUFFIXES.get(suffix)
    if label and not findings:
        findings.append(
            _incomplete(
                "container_not_inspectable",
                f"This is a {label}, which this scanner cannot look inside.",
                "Opening this format needs software this scanner deliberately does "
                "not bundle, so nothing inside it has been checked. An archive "
                "nobody can inspect is a common way to move a file past a scanner "
                "— though it is also just a normal way to send a folder.",
                "Ask the student to re-send the work as a ZIP, or as loose files. "
                "If you must open it, do so on a machine you can afford to lose.",
                f"{label} ({suffix or detected})",
            )
        )

    if detected in {"unknown", "xml", "script"} and suffix in TEXTISH_SUFFIXES:
        findings.extend(general_detector.analyze_text_urls(handle, limits=limits, size=size))

    if config.use_yara:
        findings.extend(_run_yara(path, config))

    return findings


def _run_yara(path: Path, config: ScanConfig) -> List[Finding]:
    """Optional YARA pass. Absent or broken rules degrade to a stated non-result."""
    try:
        import yara
    except ImportError:
        return [
            _incomplete(
                "yara_unavailable",
                "YARA scanning was requested but the yara-python package is not "
                "installed, so no rules were run.",
                "The scan completed without the extra rule checks you asked for.",
                "Install the optional extra with:\n"
                "  pip install 'teacher-safe-local-file-scanner[yara]'",
                "yara-python missing",
            )
        ]

    rules_path = config.yara_rules_path
    try:
        if rules_path and Path(rules_path).exists():
            rules = yara.compile(filepath=str(rules_path))
        else:
            return [
                _incomplete(
                    "yara_no_rules",
                    "YARA scanning was requested but no rules file was supplied.",
                    "Without rules there is nothing for YARA to match.",
                    "Pass --yara-rules /path/to/rules.yar",
                    str(rules_path or "<none>"),
                )
            ]
        matches = rules.match(str(path), timeout=30)
    except Exception as exc:
        return [
            _incomplete(
                "yara_error",
                "The YARA rules could not be run against this file.",
                "The extra rule checks did not complete.",
                "Check the rules file compiles with yarac.",
                str(exc)[:200],
            )
        ]

    findings: List[Finding] = []
    for match in matches:
        meta = getattr(match, "meta", {}) or {}
        findings.append(
            Finding(
                code=f"yara_{match.rule}",
                title=f"YARA rule matched: {match.rule}",
                plain=str(
                    meta.get("description")
                    or f"A custom detection rule named '{match.rule}' matched this file."
                ),
                why=str(
                    meta.get("why")
                    or "This rule was supplied by your school or IT team; what it "
                    "means depends on the rule."
                ),
                action=str(meta.get("action") or "Follow your school's guidance for this rule."),
                severity=Severity.parse(meta.get("severity"), Severity.MEDIUM),
                confidence=Confidence.parse(meta.get("confidence"), Confidence.MEDIUM),
                evidence=", ".join(sorted({str(t) for t in getattr(match, "tags", [])})) or None,
                detector="yara",
            )
        )
    return findings


def scan(
    root: Path,
    config: ScanConfig,
    *,
    progress: Optional[Callable[[int, int, Path], None]] = None,
) -> List[ScanResult]:
    """Scan *root* recursively. Results are sorted worst-first."""
    targets = list(iter_targets(root, follow_symlinks=config.follow_symlinks))
    if not targets:
        LOGGER.info("No files found under %s", root)
        return []

    results: List[ScanResult] = []
    total = len(targets)
    with ThreadPoolExecutor(max_workers=max(1, config.threads)) as pool:
        futures = {pool.submit(scan_file, path, config): path for path in targets}
        for index, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            results.append(result)
            if progress is not None:
                progress(index, total, result.path)

    results.sort(key=lambda r: (-r.verdict.rank, -r.risk_score, str(r.path)))
    return results


def scanner_version() -> str:
    return __version__


__all__ = [
    "ScanConfig",
    "ScanResult",
    "scan",
    "scan_file",
    "iter_targets",
    "scanner_version",
]
