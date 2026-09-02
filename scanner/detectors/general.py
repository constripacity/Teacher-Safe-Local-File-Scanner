"""File-level checks that apply regardless of format."""
from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path
from typing import BinaryIO, List, Optional

from ..findings import Confidence, Finding, Severity
from ..limits import ScanLimits
from .base import (
    EXECUTABLE_SUFFIXES,
    EXTENSION_EXPECTATIONS,
    LURE_SUFFIXES,
    URL_RE,
    has_bidi_deception,
    has_invisible_chars,
    suffix_chain,
)

LOGGER = logging.getLogger(__name__)

DETECTOR = "general"

#: URL shorteners hide their destination, which matters in a document a student
#: is asking a teacher to click.
SHORTENER_HOSTS = frozenset(
    {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
        "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "s.id", "tiny.cc",
    }
)

EXECUTABLE_MAGICS = {
    "pe": "a Windows program",
    "elf": "a Linux program",
    "macho": "a macOS program",
    "macho-fat": "a macOS program",
}

HOST_RE = re.compile(r"^([^/@]*@)?([^/:]+)")


def _f(
    code: str,
    title: str,
    plain: str,
    why: str,
    action: str,
    severity: Severity,
    confidence: Confidence,
    evidence: Optional[str] = None,
    incomplete: bool = False,
) -> Finding:
    return Finding(
        code=code,
        title=title,
        plain=plain,
        why=why,
        action=action,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        detector=DETECTOR,
        inspection_incomplete=incomplete,
    )


def analyze_name(path: Path) -> List[Finding]:
    """Checks that need only the filename."""
    findings: List[Finding] = []
    name = path.name

    bidi = has_bidi_deception(name)
    if bidi:
        findings.append(
            _f(
                "name_bidi_override",
                "Filename uses a right-to-left override character",
                "This file's name contains an invisible character that makes the "
                "name display backwards from a certain point, so what you see is "
                "not what the file is called.",
                "The only practical use of this character in a filename is to make "
                "a program look like a picture or a document.",
                "Do not open this file. Send it to IT.",
                Severity.HIGH,
                Confidence.HIGH,
                evidence=f"{name!r} contains {bidi}",
            )
        )
    else:
        invisible = has_invisible_chars(name)
        if invisible:
            findings.append(
                _f(
                    "name_invisible_chars",
                    "Filename contains invisible characters",
                    "This file's name contains characters that do not display.",
                    "Hidden characters disguise a file's real extension. They also "
                    "arrive accidentally when a name is copied from a web page.",
                    "Rename the file before opening it, so you can see what it is.",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    evidence=f"{name!r} contains {invisible}",
                )
            )

    suffixes = suffix_chain(name)
    if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_SUFFIXES and suffixes[-2] in LURE_SUFFIXES:
        findings.append(
            _f(
                "name_double_extension",
                "File is disguised with a double extension",
                f"This file is named to look like a {suffixes[-2]} document but "
                f"actually ends in {suffixes[-1]}, which the computer runs as a "
                "program.",
                "Windows hides known file extensions by default, so 'essay.pdf.exe' "
                "appears in the folder as 'essay.pdf'. Double-clicking runs a "
                "program.",
                "Do not open this file. Send it to IT.",
                Severity.HIGH,
                Confidence.HIGH,
                evidence=name,
            )
        )
    elif suffixes and suffixes[-1] in EXECUTABLE_SUFFIXES:
        findings.append(
            _f(
                "name_executable_extension",
                "File is a program or script",
                f"This is a {suffixes[-1]} file — the computer treats it as "
                "something to run, not something to read.",
                "A submission that is a program should be expected (a computing "
                "assignment) or refused. It should never be opened by "
                "double-clicking to 'see what it is'.",
                "If this is a programming assignment, open it in a text editor. "
                "Otherwise do not open it at all.",
                Severity.HIGH,
                Confidence.HIGH,
                evidence=name,
            )
        )

    if name.startswith(".") and name not in {".", ".."}:
        findings.append(
            _f(
                "name_hidden_file",
                "File is hidden",
                "This file's name starts with a dot, which hides it from normal "
                "folder listings on macOS and Linux.",
                "Hidden files in a submission are usually operating-system leftovers "
                "(.DS_Store). Occasionally they are how something is smuggled into a "
                "folder unnoticed.",
                "No action needed unless something else was also found.",
                Severity.INFO,
                Confidence.HIGH,
                evidence=name,
            )
        )

    return findings


def analyze_content(
    handle: BinaryIO, path: Path, *, limits: ScanLimits, magic: str
) -> List[Finding]:
    """Checks that need the file's first bytes."""
    findings: List[Finding] = []
    suffix = path.suffix.lower()

    if magic in EXECUTABLE_MAGICS and suffix not in EXECUTABLE_SUFFIXES:
        findings.append(
            _f(
                "content_is_executable",
                "File contains a program, whatever it is named",
                f"Regardless of its name, the contents of this file are "
                f"{EXECUTABLE_MAGICS[magic]}.",
                "The operating system decides what to do with a file partly by its "
                "contents. A program named .txt is still a program.",
                "Do not open or run this file. Send it to IT.",
                Severity.HIGH,
                Confidence.HIGH,
                evidence=f"detected as {magic}",
            )
        )
        return findings

    expected = EXTENSION_EXPECTATIONS.get(suffix)
    if expected and magic != "unknown" and magic not in expected:
        findings.append(
            _f(
                "content_extension_mismatch",
                "File contents do not match its extension",
                f"This file is named {suffix} but its contents are "
                f"{_describe(magic)}.",
                "A mismatch is sometimes an honest rename and sometimes a disguise. "
                "Either way, the program that opens it will not do what the name "
                "suggests.",
                "Confirm with the student what this file is supposed to be before "
                "opening it.",
                Severity.MEDIUM,
                Confidence.HIGH,
                evidence=f"{suffix} file detected as {magic}",
            )
        )
    return findings


def analyze_text_urls(
    handle: BinaryIO, *, limits: ScanLimits, size: int
) -> List[Finding]:
    """Extract and assess URLs in a text-like file, bounded."""
    handle.seek(0)
    data = handle.read(min(limits.max_text_scan_bytes, size))
    if b"\x00" in data[:4096]:
        return []

    findings: List[Finding] = []
    seen: set[str] = set()
    shorteners: list[str] = []
    raw_ips: list[str] = []
    punycode: list[str] = []

    for match in URL_RE.finditer(data):
        url = match.group(0).decode("utf-8", "replace").rstrip(".,;:!?")
        if url in seen or len(seen) >= limits.max_urls_reported:
            continue
        seen.add(url)
        host = _host_of(url)
        if not host:
            continue
        if host.lower() in SHORTENER_HOSTS:
            shorteners.append(url)
        elif host.lower().startswith("xn--") or ".xn--" in host.lower():
            punycode.append(url)
        else:
            try:
                ipaddress.ip_address(host)
                raw_ips.append(url)
            except ValueError:
                pass

    if punycode:
        findings.append(
            _f(
                "url_punycode_host",
                "Link uses a lookalike internationalised domain",
                "A link in this file points at a domain written with characters "
                "that can imitate ordinary letters.",
                "Punycode domains are how 'аpple.com' (with a Cyrillic а) is made to "
                "look like 'apple.com'. It is a phishing technique.",
                "Do not click the link. Type the address you meant to visit instead.",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                evidence=", ".join(punycode[:3])[:300],
            )
        )
    if raw_ips:
        findings.append(
            _f(
                "url_raw_ip",
                "Link points at a bare IP address",
                "A link in this file goes to a numeric address rather than a "
                "website name.",
                "Legitimate sites almost always use names. A bare IP avoids domain "
                "reputation checks and is common in malicious links — though it is "
                "also how someone links to a machine on the school network.",
                "Check with IT before following it.",
                Severity.LOW,
                Confidence.MEDIUM,
                evidence=", ".join(raw_ips[:3])[:300],
            )
        )
    if shorteners:
        findings.append(
            _f(
                "url_shortener",
                "Link is shortened and hides its destination",
                f"This file contains {len(shorteners)} shortened link(s) whose real "
                "destination is not visible.",
                "A shortened link could go anywhere. Students use them constantly, "
                "so this is context rather than an accusation.",
                "Preview the link before clicking it.",
                Severity.LOW,
                Confidence.HIGH,
                evidence=", ".join(shorteners[:3])[:300],
            )
        )

    if len(data) >= limits.max_text_scan_bytes and size > limits.max_text_scan_bytes:
        findings.append(
            _f(
                "text_scan_truncated",
                "Only part of this text file was read",
                f"Only the first {limits.max_text_scan_bytes // 1024} KB were "
                "checked for links.",
                "Content past the limit has not been examined.",
                "Treat the link check as partial.",
                Severity.INFO,
                Confidence.HIGH,
                evidence=f"{size} byte file",
                incomplete=True,
            )
        )
    return findings


def _host_of(url: str) -> str:
    try:
        rest = url.split("//", 1)[1]
    except IndexError:
        return ""
    match = HOST_RE.match(rest)
    if not match:
        return ""
    host = match.group(2)
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _describe(kind: str) -> str:
    return {
        "pe": "a Windows program",
        "elf": "a Linux program",
        "macho": "a macOS program",
        "macho-fat": "a macOS program",
        "zip": "a ZIP archive",
        "pdf": "a PDF",
        "png": "a PNG image",
        "jpeg": "a JPEG image",
        "gif": "a GIF image",
        "ole": "an old-format Office document",
        "rtf": "an RTF document",
        "script": "a script",
        "rar": "a RAR archive",
        "7z": "a 7-Zip archive",
        "gzip": "a gzip archive",
        "xml": "an XML file",
    }.get(kind, f"of type '{kind}'")


__all__ = ["analyze_name", "analyze_content", "analyze_text_urls"]
