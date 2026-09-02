"""Static inspection of Office documents (OOXML and legacy OLE).

No macro is ever executed and no document is ever rendered. The OOXML path
reads the ZIP container's part names and relationship files; the legacy path
looks at the compound-file directory only.

XML is parsed with :mod:`defusedxml` when it is installed. When it is not, this
module falls back to a **byte-level scan**, never to :mod:`xml.etree`, because a
student submission is untrusted input and stdlib ElementTree is vulnerable to
entity-expansion attacks.
"""
from __future__ import annotations

import logging
import re
import zipfile
from pathlib import Path
from typing import BinaryIO, List, Optional, Sequence

from ..findings import Confidence, Finding, Severity
from ..limits import ScanLimits

LOGGER = logging.getLogger(__name__)

DETECTOR = "office"

try:  # pragma: no cover - exercised by whichever branch the host provides
    from defusedxml import ElementTree as _SafeET

    HAVE_DEFUSEDXML = True
except ImportError:  # pragma: no cover
    _SafeET = None
    HAVE_DEFUSEDXML = False

MACRO_PART_RE = re.compile(r"(^|/)vbaProject\.bin$", re.IGNORECASE)
MACRO_SIGNED_RE = re.compile(r"(^|/)vbaProjectSignature\.bin$", re.IGNORECASE)
EMBEDDED_OBJECT_RE = re.compile(
    r"embeddings/.+\.(bin|xlsx|docx|pptx|xls|doc|ppt|emf)$", re.IGNORECASE
)
ACTIVEX_RE = re.compile(r"activeX/activeX\d+\.(xml|bin)$", re.IGNORECASE)
PRINTER_SETTINGS_RE = re.compile(r"printerSettings/", re.IGNORECASE)

#: Relationship types that reach outside the document when it is opened.
EXTERNAL_RELATIONSHIP_TYPES = {
    "attachedTemplate": (
        "remote template",
        "The document is configured to load a template from another location "
        "when it opens.",
        "Remote template loading is one of the few ways a document that contains "
        "no macros of its own can still fetch and run one. It is a well-known "
        "phishing technique and almost never appears in student work.",
        Severity.HIGH,
        Confidence.HIGH,
    ),
    "oleObject": (
        "linked object",
        "The document links to an object stored somewhere else.",
        "A linked OLE object causes the document to reach out to another file "
        "when opened, which can be used to fetch content the scanner never saw.",
        Severity.MEDIUM,
        Confidence.MEDIUM,
    ),
    "frame": (
        "external frame",
        "The document embeds a frame pointing at an external document.",
        "External frames pull in content from elsewhere at open time.",
        Severity.MEDIUM,
        Confidence.MEDIUM,
    ),
    "subDocument": (
        "external subdocument",
        "The document includes another document stored elsewhere.",
        "Subdocument links cause content to be fetched when the file opens.",
        Severity.MEDIUM,
        Confidence.MEDIUM,
    ),
}

#: Legacy compound-file directory entry names that indicate a macro project.
OLE_MACRO_MARKERS = (
    b"V\x00B\x00A\x00",
    b"_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T",
)
OLE_EQUATION_MARKER = b"E\x00q\x00u\x00a\x00t\x00i\x00o\x00n\x00 \x003"


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


def analyze_office(
    handle: BinaryIO, *, limits: ScanLimits, suffix: str = ""
) -> List[Finding]:
    """Inspect an Office document. Dispatches on container format, not extension."""
    handle.seek(0)
    head = handle.read(8)
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return _analyze_legacy_ole(handle, limits=limits, suffix=suffix)
    if head.startswith(b"PK"):
        return _analyze_ooxml(handle, limits=limits, suffix=suffix)
    if suffix in {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}:
        return [
            _f(
                "office_container_mismatch",
                "Not actually an Office document",
                f"This file is named like an Office document ({suffix}) but its "
                "contents are not in any Office format.",
                "A file whose real type does not match its name is either broken or "
                "deliberately disguised. Either way the Office checks could not run.",
                "Do not open it by double-clicking. Ask the student to re-send it.",
                Severity.MEDIUM,
                Confidence.HIGH,
                evidence=f"magic bytes {head[:4]!r}",
                incomplete=True,
            )
        ]
    return []


# --------------------------------------------------------------------------
# OOXML (.docx / .xlsx / .pptx and their macro-enabled variants)
# --------------------------------------------------------------------------
def _analyze_ooxml(handle: BinaryIO, *, limits: ScanLimits, suffix: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        handle.seek(0)
        archive = zipfile.ZipFile(handle)
    except (zipfile.BadZipFile, OSError) as exc:
        return [
            _f(
                "office_unreadable",
                "Office document could not be opened",
                "This document's internal structure is damaged, so it could not be "
                "checked.",
                "A document that will not open has not been cleared as safe.",
                "Ask the student to re-save and re-send it.",
                Severity.LOW,
                Confidence.HIGH,
                evidence=str(exc)[:200],
                incomplete=True,
            )
        ]

    with archive:
        try:
            names = archive.namelist()[: limits.max_archive_members]
        except Exception as exc:  # pragma: no cover
            return [
                _f(
                    "office_unreadable",
                    "Office document index could not be read",
                    "This document's table of contents is corrupt.",
                    "Nothing inside it could be checked.",
                    "Ask for the file again.",
                    Severity.LOW,
                    Confidence.HIGH,
                    evidence=str(exc)[:200],
                    incomplete=True,
                )
            ]

        macro_parts = [n for n in names if MACRO_PART_RE.search(n)]
        if macro_parts:
            signed = any(MACRO_SIGNED_RE.search(n) for n in names)
            findings.append(
                _f(
                    "office_macro_present",
                    "Document contains a macro project",
                    "This document has macros — small programs stored inside the "
                    "document that can run when it is opened.",
                    "Macros are the single most common way a document infects a "
                    "computer. Some legitimate coursework uses them (spreadsheet "
                    "classes, accessibility templates), but a macro in an essay is "
                    "not normal."
                    + (
                        " This project carries a digital signature, which is mildly "
                        "reassuring but does not prove it is safe."
                        if signed
                        else ""
                    ),
                    "Do not open this in Word or Excel. If you must read the text, "
                    "open it in a viewer that does not run macros, or ask IT.",
                    Severity.HIGH,
                    Confidence.HIGH,
                    evidence=", ".join(macro_parts[:3]),
                )
            )
        elif suffix in {".docm", ".xlsm", ".pptm"}:
            findings.append(
                _f(
                    "office_macro_extension_only",
                    "Macro-enabled file type with no macro inside",
                    f"This file uses the macro-enabled {suffix} format, but no macro "
                    "code was actually found inside it.",
                    "Saving as a macro-enabled type without macros is harmless and "
                    "common. It is noted only so the file type does not surprise you.",
                    "No action needed on this point alone.",
                    Severity.INFO,
                    Confidence.HIGH,
                    evidence=suffix,
                )
            )

        findings.extend(_external_relationships(archive, names, limits))

        embedded = [n for n in names if EMBEDDED_OBJECT_RE.search(n)]
        if embedded:
            findings.append(
                _f(
                    "office_embedded_object",
                    "Document has other files embedded inside it",
                    f"There are {len(embedded)} file(s) packaged inside this document.",
                    "Embedding is how a document carries a payload without looking "
                    "like it does — but it is also how someone attaches a spreadsheet "
                    "to a report. The embedded files were listed, not opened.",
                    "Do not double-click the embedded object. Preview the document "
                    "in a read-only viewer instead.",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    evidence=", ".join(Path(n).name for n in embedded[:5]),
                )
            )

        activex = [n for n in names if ACTIVEX_RE.search(n)]
        if activex:
            findings.append(
                _f(
                    "office_activex",
                    "Document contains ActiveX controls",
                    f"This document contains {len(activex)} ActiveX control(s) — "
                    "embedded interactive components.",
                    "ActiveX controls can execute code on Windows when the document "
                    "is opened and are rarely needed in coursework.",
                    "Do not open this on Windows without IT clearing it first.",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    evidence=", ".join(Path(n).name for n in activex[:5]),
                )
            )

        dde = _scan_for_dde(archive, names, limits)
        if dde:
            findings.append(dde)

    return findings[: limits.max_findings_per_file]


def _external_relationships(
    archive: zipfile.ZipFile, names: Sequence[str], limits: ScanLimits
) -> List[Finding]:
    """Find relationship parts whose target lives outside the document."""
    findings: List[Finding] = []
    rels = [n for n in names if n.lower().endswith(".rels")][:64]
    seen_types: set[str] = set()

    for rel_name in rels:
        raw = _read_bounded(archive, rel_name, 512 * 1024)
        if raw is None:
            continue
        for rel_type, target, mode in _iter_relationships(raw):
            if mode.lower() != "external":
                continue
            short = rel_type.rsplit("/", 1)[-1]
            if short in seen_types:
                continue
            info = EXTERNAL_RELATIONSHIP_TYPES.get(short)
            if info is None:
                if short in {"hyperlink", "image", "package"}:
                    continue
                info = (
                    short,
                    "The document points at something outside itself when opened.",
                    "External references cause the document to fetch content the "
                    "scanner has not seen.",
                    Severity.LOW,
                    Confidence.LOW,
                )
            seen_types.add(short)
            label, plain, why, severity, confidence = info
            findings.append(
                _f(
                    f"office_external_{short.lower()}",
                    f"Document links out to a {label}",
                    plain,
                    why,
                    "Do not open this document normally. Show the link target to IT.",
                    severity,
                    confidence,
                    evidence=f"{rel_name}: {target[:200]}",
                )
            )
    return findings


def _iter_relationships(raw: bytes):
    """Yield ``(type, target, targetmode)`` from an OOXML .rels part.

    Uses defusedxml when available. The regex fallback is intentionally a *byte
    scan*, not an XML parse, so no entity expansion is possible either way.
    """
    if HAVE_DEFUSEDXML and _SafeET is not None:
        try:
            root = _SafeET.fromstring(raw, forbid_dtd=True, forbid_entities=True)
        except Exception as exc:  # pragma: no cover - malformed part
            LOGGER.debug("relationship XML parse failed: %s", exc)
        else:
            for element in root.iter():
                if not element.tag.endswith("Relationship"):
                    continue
                yield (
                    element.get("Type", ""),
                    element.get("Target", ""),
                    element.get("TargetMode", ""),
                )
            return

    for match in re.finditer(rb"<Relationship\b[^>]*>", raw, re.IGNORECASE):
        tag = match.group(0)
        yield (
            _tag_attr(tag, b"Type"),
            _tag_attr(tag, b"Target"),
            _tag_attr(tag, b"TargetMode"),
        )


def _tag_attr(tag: bytes, name: bytes) -> str:
    """Read one attribute out of a single XML start tag, as bytes."""
    found = re.search(name + rb'\s*=\s*"([^"]*)"', tag, re.IGNORECASE)
    return found.group(1).decode("utf-8", "replace") if found else ""


def _scan_for_dde(
    archive: zipfile.ZipFile, names: Sequence[str], limits: ScanLimits
) -> Optional[Finding]:
    """Look for DDEAUTO/DDE field codes in the main document body."""
    targets = [
        n
        for n in names
        if n.lower() in {"word/document.xml", "word/endnotes.xml", "word/footnotes.xml"}
    ]
    for name in targets:
        raw = _read_bounded(archive, name, 2 * 1024 * 1024)
        if raw is None:
            continue
        if re.search(rb"\bDDEAUTO\b|\bDDE\s", raw, re.IGNORECASE):
            return _f(
                "office_dde_field",
                "Document contains a DDE field",
                "This document contains an instruction that asks another program "
                "to run when the document opens.",
                "DDE fields were widely used to launch commands from Word documents "
                "without any macro at all. Modern Office blocks them by default, but "
                "not every version does.",
                "Do not open this document. Send it to IT.",
                Severity.HIGH,
                Confidence.MEDIUM,
                evidence=f"{name}: DDE field code present",
            )
    return None


def _read_bounded(archive: zipfile.ZipFile, name: str, cap: int) -> Optional[bytes]:
    try:
        with archive.open(name, "r") as part:
            return part.read(cap)
    except (KeyError, RuntimeError, zipfile.BadZipFile, OSError, EOFError, NotImplementedError):
        return None


# --------------------------------------------------------------------------
# Legacy OLE compound files (.doc / .xls / .ppt)
# --------------------------------------------------------------------------
def _analyze_legacy_ole(handle: BinaryIO, *, limits: ScanLimits, suffix: str) -> List[Finding]:
    """Bounded scan of an OLE compound file's directory strings.

    A full CFB directory walk would be better, but a bounded byte scan for the
    UTF-16 stream names that macro storage always produces gets the same answer
    without adding a dependency or a parser that runs on hostile input.
    """
    handle.seek(0)
    data = handle.read(min(limits.max_read_bytes, 4 * 1024 * 1024))
    findings: List[Finding] = []

    if any(marker in data for marker in OLE_MACRO_MARKERS):
        findings.append(
            _f(
                "office_legacy_macro",
                "Legacy Office file contains macro storage",
                "This is an older-format Office file and it contains macro storage — "
                "program code saved inside the document.",
                "Older .doc/.xls files carry macros in a form that many tools do not "
                "inspect, which is exactly why they are still used to deliver malware.",
                "Do not open this in Word or Excel. Ask the student to re-save it as "
                ".docx and re-send.",
                Severity.HIGH,
                Confidence.MEDIUM,
                evidence="VBA storage stream present in compound file",
            )
        )

    if OLE_EQUATION_MARKER in data:
        findings.append(
            _f(
                "office_equation_object",
                "Legacy file embeds an Equation Editor object",
                "This document embeds an object created by the old Equation Editor.",
                "The Equation Editor component had well-known memory-corruption bugs "
                "that were heavily exploited; documents using it are treated with "
                "suspicion even though maths coursework legitimately contains "
                "equations.",
                "If this is a maths assignment, ask for a PDF instead. Otherwise send "
                "it to IT.",
                Severity.MEDIUM,
                Confidence.LOW,
                evidence="Equation.3 object present",
            )
        )

    if len(data) >= limits.max_read_bytes:
        findings.append(
            _f(
                "office_legacy_truncated",
                "Legacy document was only partly inspected",
                "This document is larger than the scanner reads, so only the first "
                "part of it was checked.",
                "Content past the inspection limit has not been examined.",
                "Treat the result as a partial check.",
                Severity.LOW,
                Confidence.HIGH,
                evidence=f"read {len(data)} bytes",
                incomplete=True,
            )
        )

    if suffix in {".docx", ".xlsx", ".pptx"}:
        findings.append(
            _f(
                "office_container_mismatch",
                "Modern extension, legacy contents",
                f"This file is named {suffix} but is actually an old-format Office "
                "document inside.",
                "The mismatch means whatever opens it will not behave the way the "
                "name suggests. It is sometimes a rename mistake and sometimes "
                "deliberate.",
                "Ask the student to re-save it properly before you open it.",
                Severity.MEDIUM,
                Confidence.HIGH,
                evidence=f"OLE compound file with {suffix} extension",
            )
        )

    return findings[: limits.max_findings_per_file]


__all__ = ["analyze_office", "HAVE_DEFUSEDXML"]
