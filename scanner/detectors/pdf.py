"""Bounded static inspection of PDF structure.

The PDF is never rendered and never passed to a PDF engine. This module scans
bytes for structural markers and reports what it saw.

Two bugs in the original implementation are fixed here and are worth naming:

* the old scanner searched 4 KB windows with a **10-byte** overlap while looking
  for tokens up to 13 bytes long, so a token straddling a window boundary was
  silently missed. Overlap is now derived from the longest token;
* ``/JS`` was counted separately from ``/JavaScript``, so one JavaScript action
  produced two findings and inflated the score. Markers are now grouped, and
  each group fires once.
"""
from __future__ import annotations

import logging
import re
from typing import BinaryIO, Dict, List, Optional, Tuple

from ..findings import Confidence, Finding, Severity
from ..limits import ScanLimits
from .base import iter_windows, read_head, read_tail

LOGGER = logging.getLogger(__name__)

DETECTOR = "pdf"

# (code, title, [byte markers], plain, why, action, severity, confidence)
_MARKER_GROUPS: List[Tuple[str, str, List[bytes], str, str, str, Severity, Confidence]] = [
    (
        "pdf_open_action",
        "PDF runs something automatically when opened",
        [b"/OpenAction", b"/AA"],
        "This PDF is set up to do something on its own the moment it is opened, "
        "before you click anything.",
        "Automatic actions are how a PDF starts working without the reader doing "
        "anything. Some are harmless (jump to a page, play a sound); the mechanism "
        "is also the standard delivery step for PDF exploits.",
        "Open it in a browser's built-in PDF viewer, which sandboxes it, or ask IT.",
        Severity.MEDIUM,
        Confidence.MEDIUM,
    ),
    (
        "pdf_javascript",
        "PDF contains JavaScript",
        [b"/JavaScript", b"/JS"],
        "This PDF contains JavaScript — program code that runs inside the PDF "
        "reader.",
        "Very few documents need JavaScript; interactive forms are the main honest "
        "use. In student work it is unusual, and it is the component most PDF "
        "exploits rely on.",
        "Do not open it in Adobe Reader. A browser PDF viewer is much safer, or "
        "ask the student for a plain export.",
        Severity.HIGH,
        Confidence.MEDIUM,
    ),
    (
        "pdf_launch_action",
        "PDF tries to launch another program",
        [b"/Launch"],
        "This PDF contains an instruction to start another program on your "
        "computer.",
        "There is no legitimate reason for a coursework PDF to launch an "
        "application. This is a direct execution attempt.",
        "Do not open this file. Send it to IT.",
        Severity.HIGH,
        Confidence.HIGH,
    ),
    (
        "pdf_embedded_file",
        "PDF has another file attached inside it",
        [b"/EmbeddedFile", b"/Filespec"],
        "This PDF carries another file inside it as an attachment.",
        "Attachments ride along invisibly and are opened by a separate click. It is "
        "a normal PDF feature and also a normal way to smuggle an executable past "
        "an email filter.",
        "Do not open the attachment. Read the PDF in a browser viewer.",
        Severity.MEDIUM,
        Confidence.MEDIUM,
    ),
    (
        "pdf_submit_form",
        "PDF can send data somewhere when submitted",
        [b"/SubmitForm", b"/GoToR", b"/URI"],
        "This PDF contains links or form actions that reach out to the internet.",
        "Ordinary hyperlinks look exactly like this, so on its own it means very "
        "little. It matters only alongside something else.",
        "Hover before clicking any link inside; do not enter credentials into a PDF "
        "form.",
        Severity.LOW,
        Confidence.LOW,
    ),
    (
        "pdf_xfa_form",
        "PDF uses an XFA form",
        [b"/XFA"],
        "This PDF uses the older XFA form technology.",
        "XFA forms are processed by a large, historically bug-prone part of Adobe "
        "Reader. Most viewers no longer support them at all.",
        "Prefer a browser viewer; do not open in Adobe Reader.",
        Severity.LOW,
        Confidence.MEDIUM,
    ),
]

_LONGEST_MARKER = max(len(m) for _, _, ms, *_ in _MARKER_GROUPS for m in ms)

ENCRYPT_RE = re.compile(rb"/Encrypt\b")
EOF_RE = re.compile(rb"%%EOF")
HEADER_RE = re.compile(rb"%PDF-(\d+\.\d+)")
OBJSTM_RE = re.compile(rb"/ObjStm\b")


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


def analyze_pdf(
    handle: BinaryIO, *, limits: ScanLimits, size: Optional[int] = None
) -> List[Finding]:
    findings: List[Finding] = []

    head = read_head(handle, 1024)
    header = HEADER_RE.search(head)
    # A conforming PDF starts at byte 0. A header found further in means there
    # is a prefix, which is the shape of a polyglot file.
    if header is None or header.start() != 0:
        # Some real PDFs have junk before %PDF-; the spec tolerates it, readers do too.
        handle.seek(0)
        prefix = handle.read(min(4096, limits.head_bytes))
        offset = prefix.find(b"%PDF-")
        if offset > 0:
            findings.append(
                _f(
                    "pdf_header_offset",
                    "PDF header is not at the start of the file",
                    f"There are {offset} bytes of other data in front of where this "
                    "PDF actually begins.",
                    "Data in front of the PDF header is how a single file is made to "
                    "be two things at once — a PDF to one program and something else "
                    "to another.",
                    "Do not open this file. Send it to IT.",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    evidence=f"%PDF- found at byte {offset}",
                )
            )
        elif offset < 0:
            return [
                _f(
                    "pdf_not_a_pdf",
                    "File is not a PDF",
                    "This file is named like a PDF but does not contain a PDF header.",
                    "A file whose contents do not match its name has not been checked "
                    "as what it claims to be.",
                    "Do not open it by double-clicking. Ask for it again.",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    evidence=f"first bytes {head[:8]!r}",
                    incomplete=True,
                )
            ]

    seen: Dict[str, bytes] = {}
    truncated = False
    scanned = 0
    for _offset, window in iter_windows(
        handle, limits=limits, window=512 * 1024, overlap=_LONGEST_MARKER
    ):
        scanned = max(scanned, _offset + len(window))
        for code, title, markers, plain, why, action, severity, confidence in _MARKER_GROUPS:
            if code in seen:
                continue
            for marker in markers:
                if marker in window:
                    seen[code] = marker
                    findings.append(
                        _f(code, title, plain, why, action, severity, confidence,
                           evidence=marker.decode("ascii"))
                    )
                    break
        if ENCRYPT_RE.search(window) and "pdf_encrypted" not in seen:
            seen["pdf_encrypted"] = b"/Encrypt"
            findings.append(
                _f(
                    "pdf_encrypted",
                    "PDF is encrypted",
                    "This PDF is encrypted, so parts of its internal structure could "
                    "not be examined.",
                    "Most encrypted PDFs are simply protected against editing or "
                    "printing and open fine. But encryption also hides content from "
                    "scanners, so this file is only partly checked.",
                    "Treat it as unchecked rather than clean.",
                    Severity.LOW,
                    Confidence.HIGH,
                    evidence="/Encrypt dictionary present",
                    incomplete=True,
                )
            )

    if size is not None and scanned < size:
        truncated = True

    if truncated:
        findings.append(
            _f(
                "pdf_truncated_scan",
                "PDF was only partly scanned",
                f"Only the first {scanned // (1024 * 1024)} MB of this PDF were "
                "examined because of the scanner's size limit.",
                "Anything past the limit has not been looked at.",
                "Treat the result as a partial check.",
                Severity.LOW,
                Confidence.HIGH,
                evidence=f"scanned {scanned} of {size} bytes",
                incomplete=True,
            )
        )

    findings.extend(_appended_data(handle, limits, size))
    return findings[: limits.max_findings_per_file]


def _appended_data(handle: BinaryIO, limits: ScanLimits, size: Optional[int]) -> List[Finding]:
    """Flag substantial content after the final ``%%EOF`` marker.

    Incremental updates legitimately leave one ``%%EOF`` mid-file, so this only
    looks after the *last* one, and only complains about a meaningful amount of
    trailing data rather than the whitespace real writers leave behind.
    """
    tail = read_tail(handle, limits.tail_bytes, size=size)
    if not tail:
        return []
    last = tail.rfind(b"%%EOF")
    if last < 0:
        return [
            _f(
                "pdf_no_eof",
                "PDF has no end-of-file marker",
                "This PDF does not end the way a complete PDF should.",
                "A missing end marker usually means a truncated or corrupted "
                "download, but it also appears in hand-built malformed PDFs "
                "designed to confuse readers.",
                "Ask the student to re-send it.",
                Severity.LOW,
                Confidence.MEDIUM,
                evidence="no %%EOF in final bytes",
                incomplete=True,
            )
        ]
    trailing = tail[last + 5 :].strip(b"\r\n \t\x00")
    if len(trailing) > 64:
        return [
            _f(
                "pdf_appended_data",
                "Extra data is hidden after the end of the PDF",
                f"There are {len(trailing):,} bytes of content after the point where "
                "this PDF officially ends.",
                "A PDF reader stops at the end marker, so anything after it is "
                "invisible when you open the file — which is exactly why payloads "
                "get stored there.",
                "Do not open this file. Send it to IT.",
                Severity.MEDIUM,
                Confidence.MEDIUM,
                evidence=f"{len(trailing)} bytes after final %%EOF, starts {trailing[:16]!r}",
            )
        ]
    return []


__all__ = ["analyze_pdf"]
