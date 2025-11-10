"""Static detectors for the Teacher-Safe Local File Scanner.

Each detector is defensive-only and examines files without executing them.
Detectors return dictionaries describing issues but never raise fatal errors.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

from . import utils

LOGGER = logging.getLogger(__name__)


SUSPICIOUS_EXECUTABLE_SUFFIXES = {
    ".exe",
    ".bat",
    ".cmd",
    ".scr",
    ".pif",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".dll",
}


PDF_TOKENS = [b"/JAVASCRIPT", b"/JS", b"/OPENACTION", b"/LAUNCH", b"/EMBEDDEDFILE", b"/AA"]
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
PUNYCODE_PREFIX = "xn--"


def _issue(code: str, description: str, evidence: str | None = None) -> Dict[str, str]:
    issue = {"code": code, "description": description}
    if evidence is not None:
        issue["evidence"] = evidence
    return issue


def detect_double_extension(path: Path) -> Optional[Dict[str, str]]:
    """Flag filenames that use a double extension pattern."""
    suffixes = [suffix.lower() for suffix in path.suffixes]
    if len(suffixes) < 2:
        return None
    primary, secondary = suffixes[-2], suffixes[-1]
    disguising = {".pdf", ".doc", ".docx", ".txt", ".png", ".jpg"}
    if primary in disguising and secondary in SUSPICIOUS_EXECUTABLE_SUFFIXES:
        return _issue(
            "double_extension",
            "Filename uses double extension pattern",
            evidence=path.name,
        )
    if secondary in {".exe", ".bat"} and primary not in SUSPICIOUS_EXECUTABLE_SUFFIXES:
        return _issue(
            "double_extension",
            "Suspicious trailing executable extension",
            evidence=path.name,
        )
    return None


def detect_pe_headers(path: Path) -> Optional[Dict[str, str]]:
    """Detect Windows PE headers based on the 'MZ' magic string."""
    head = utils.safe_read_head(path, 2)
    if head.startswith(b"MZ"):
        return _issue("pe_header", "File starts with MZ header indicative of a Windows executable")
    return None


def detect_zip_contents(path: Path) -> List[Dict[str, str]]:
    """Inspect ZIP archives for suspicious embedded content."""
    findings: List[Dict[str, str]] = []
    members = utils.safe_list_zip_members(path)
    for name in members:
        lname = name.lower()
        if len(name) > 180:
            findings.append(
                _issue("zip_long_name", "Archive member has unusually long name", evidence=name)
            )
        if "\x00" in name:
            findings.append(
                _issue("zip_nul_byte", "Archive member name contains NUL byte", evidence=name)
            )
        if any(lname.endswith(ext) for ext in SUSPICIOUS_EXECUTABLE_SUFFIXES):
            findings.append(
                _issue("exe_in_zip", "Found executable file inside archive", evidence=name)
            )
        if detect_double_extension(Path(name)):
            findings.append(
                _issue("zip_double_extension", "Archive member has double extension", evidence=name)
            )
        if name.endswith("vbaProject.bin"):
            findings.append(
                _issue(
                    "zip_vba_project",
                    "Archive contains potential Office macro store",
                    evidence=name,
                )
            )
    return findings


def detect_pdf_risks(path: Path) -> List[Dict[str, str]]:
    """Search for risky PDF constructs such as JavaScript actions."""
    findings: List[Dict[str, str]] = []
    try:
        with path.open("rb") as handle:
            buffer = b""
            while True:
                chunk = handle.read(4096)
                if not chunk:
                    break
                combined = (buffer + chunk).upper()
                for token in PDF_TOKENS:
                    if token in combined:
                        token_name = token.decode("ascii")
                        findings.append(
                            _issue("pdf_token", f"PDF contains token {token_name}", token_name)
                        )
                buffer = combined[-10:]
    except (OSError, IOError) as exc:
        LOGGER.warning("Unable to scan PDF %s: %s", path, exc)
    return findings


def detect_image_appended_data(path: Path) -> Optional[Dict[str, str]]:
    """Detect data appended after image end markers."""
    data = utils.safe_read_tail(path, 1024 * 8)
    if not data:
        return None
    if path.suffix.lower() in {".png"}:
        if b"IEND" in data:
            index = data.rfind(b"IEND")
            trailer = data[index + 4 :]
            if trailer.strip(b"\x00"):
                return _issue("image_trailing_data", "PNG file contains data after IEND chunk")
    if path.suffix.lower() in {".jpg", ".jpeg"}:
        marker = b"\xFF\xD9"
        if marker in data:
            index = data.rfind(marker)
            if data[index + 2 :].strip(b"\x00"):
                return _issue("image_trailing_data", "JPEG file contains data after end marker")
    return None


def detect_office_macro(path: Path) -> Optional[Dict[str, str]]:
    """Detect Office documents likely containing macros."""
    suffix = path.suffix.lower()
    if suffix in {".docm", ".xlsm", ".pptm"}:
        return _issue("office_macro_extension", "Office document type supports embedded macros")
    if suffix in {".docx", ".pptx", ".xlsx"}:
        members = utils.safe_list_zip_members(path)
        for name in members:
            if name.endswith("vbaProject.bin"):
                return _issue("office_macro_container", "Office document contains vbaProject.bin")
    return None


def extract_urls_and_flag(path: Path, *, max_bytes: int = 512_000) -> List[Dict[str, str]]:
    """Extract URLs from text files and flag suspicious patterns."""
    findings: List[Dict[str, str]] = []
    try:
        size = path.stat().st_size
        if size > max_bytes:
            LOGGER.debug("Skipping URL extraction for %s due to size", path)
            return findings
    except OSError as exc:
        LOGGER.warning("Unable to stat %s: %s", path, exc)
        return findings

    if not utils.is_text_file(path):
        return findings

    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            text = handle.read(max_bytes)
    except (OSError, IOError) as exc:
        LOGGER.warning("Unable to read text file %s: %s", path, exc)
        return findings

    for match in URL_RE.findall(text):
        if "://" not in match:
            continue
        host_part = match.split("//", 1)[1].split("/", 1)[0]
        if host_part.startswith(PUNYCODE_PREFIX) or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host_part):
            findings.append(_issue("url_suspicious", "Suspicious URL host", evidence=match))
        else:
            findings.append(_issue("url", "URL found in document", evidence=match))
    return findings
