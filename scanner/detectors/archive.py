"""Bounded static analysis of ZIP-family archives.

What this detector does **not** do is as important as what it does:

* it never extracts to disk, so a traversal path can never be written;
* it reads the central directory, not the payload, for structural checks;
* when it must look inside a nested archive it streams a bounded number of
  bytes through an in-memory buffer and stops;
* every loop is capped by :class:`~scanner.limits.ScanLimits`.

Encrypted entries are reported as *inspection incomplete*, never as clean.
"""
from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path
from typing import BinaryIO, List, Optional

from ..findings import Confidence, Finding, Severity
from ..limits import ScanLimits
from .base import (
    EXECUTABLE_SUFFIXES,
    LURE_SUFFIXES,
    has_bidi_deception,
    has_invisible_chars,
    looks_like_path_escape,
    suffix_chain,
)

LOGGER = logging.getLogger(__name__)

DETECTOR = "archive"

#: Members that make an OOXML container a document rather than a plain ZIP.
OOXML_MARKERS = ("[Content_Types].xml", "_rels/.rels")

#: Suffixes that are genuinely *containers of other files* and therefore worth
#: recursing into. OOXML documents (.docx/.xlsx/.pptx) are also ZIPs, but they
#: are documents: they get their own Office analysis and must not be reported as
#: "an archive inside an archive", which would flag every normal submission.
CONTAINER_SUFFIXES = frozenset({".zip", ".jar", ".apk"})


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
    **extra: object,
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
        extra=dict(extra),
    )


def analyze_archive(
    handle: BinaryIO,
    *,
    limits: ScanLimits,
    display_name: str = "",
    depth: int = 0,
) -> List[Finding]:
    """Inspect a ZIP-family archive without extracting it."""
    findings: List[Finding] = []
    prefix = f"{display_name}!" if display_name else ""

    try:
        handle.seek(0)
        archive = zipfile.ZipFile(handle)
    except zipfile.BadZipFile as exc:
        return [
            _f(
                "archive_corrupt",
                "Archive could not be opened",
                "This ZIP file is damaged or is not really a ZIP file, so its "
                "contents could not be listed.",
                "A file that will not open cannot be checked. It may simply be a "
                "broken upload, but a damaged container is also a way to hide "
                "contents from scanners.",
                "Ask the student to re-send the file. Do not try to repair it yourself.",
                Severity.LOW,
                Confidence.HIGH,
                evidence=str(exc)[:200],
                incomplete=True,
            )
        ]
    except OSError as exc:  # pragma: no cover - filesystem dependent
        return [
            _f(
                "archive_unreadable",
                "Archive could not be read",
                "The scanner could not read this archive from disk.",
                "An unreadable file has not been checked at all.",
                "Check file permissions and try again.",
                Severity.LOW,
                Confidence.HIGH,
                evidence=str(exc)[:200],
                incomplete=True,
            )
        ]

    with archive:
        try:
            infolist = archive.infolist()
        except Exception as exc:  # pragma: no cover - hostile central directory
            return [
                _f(
                    "archive_directory_unreadable",
                    "Archive index is malformed",
                    "The archive's table of contents is corrupt, so its file list "
                    "could not be read.",
                    "A malformed index prevents any inspection of what is inside.",
                    "Ask for the file again in a different format.",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    evidence=str(exc)[:200],
                    incomplete=True,
                )
            ]

        member_count = len(infolist)
        if member_count > limits.max_archive_members:
            findings.append(
                _f(
                    "archive_member_flood",
                    "Archive contains an extreme number of entries",
                    f"This archive lists {member_count:,} files. Only the first "
                    f"{limits.max_archive_members:,} were checked.",
                    "Archives with enormous entry counts are used to exhaust the "
                    "memory of whatever opens them, and to bury one bad file among "
                    "thousands of harmless ones.",
                    "Do not open this archive. Ask the student to submit their work "
                    "as individual files.",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    evidence=f"{member_count} entries",
                    incomplete=True,
                    member_count=member_count,
                )
            )
            infolist = infolist[: limits.max_archive_members]

        is_ooxml = any(info.filename in OOXML_MARKERS for info in infolist)
        total_uncompressed = 0
        seen_escape = False
        seen_encrypted = False
        nested_candidates: list[zipfile.ZipInfo] = []

        for info in infolist:
            name = info.filename
            lowered = name.lower()
            total_uncompressed += info.file_size

            # -- traversal ------------------------------------------------
            if not seen_escape and looks_like_path_escape(name):
                seen_escape = True
                findings.append(
                    _f(
                        "archive_path_traversal",
                        "Archive entry escapes its own folder",
                        "One of the files inside this archive is set to unpack "
                        "somewhere outside the folder you unzip it into.",
                        "This is how an archive overwrites a file elsewhere on the "
                        "computer — a startup script or a configuration file — the "
                        "moment it is extracted. There is no legitimate reason for a "
                        "student submission to do this.",
                        "Do not extract this archive. Send it to IT.",
                        Severity.HIGH,
                        Confidence.HIGH,
                        evidence=f"{prefix}{name}"[:300],
                    )
                )

            # -- encryption -----------------------------------------------
            if not seen_encrypted and (info.flag_bits & 0x1):
                seen_encrypted = True
                findings.append(
                    _f(
                        "archive_encrypted",
                        "Archive is password protected",
                        "This archive is locked with a password, so the scanner "
                        "could not look inside it.",
                        "Password-protected archives are a standard way to smuggle "
                        "files past scanners, because nothing — including antivirus "
                        "— can read the contents. It is also, often, a student who "
                        "read a tutorial. Either way it has not been checked.",
                        "Do not open it. Ask the student to re-send the work "
                        "without a password.",
                        Severity.MEDIUM,
                        Confidence.HIGH,
                        evidence=f"{prefix}{name}"[:300],
                        incomplete=True,
                    )
                )

            # -- compression ratio (bomb indicator) ------------------------
            if info.compress_size > 512 and info.file_size > 8 * 1024 * 1024:
                ratio = info.file_size / max(info.compress_size, 1)
                if ratio > limits.max_compression_ratio:
                    findings.append(
                        _f(
                            "archive_bomb_ratio",
                            "Entry expands to a wildly larger size",
                            f"One entry is {_human(info.compress_size)} on disk but "
                            f"claims to unpack to {_human(info.file_size)} "
                            f"({ratio:,.0f} times larger).",
                            "This is the signature of a decompression bomb: a tiny "
                            "file that fills the disk or exhausts memory when opened.",
                            "Do not extract this archive.",
                            Severity.HIGH,
                            Confidence.MEDIUM,
                            evidence=f"{prefix}{name} {info.compress_size}->{info.file_size}"[:300],
                            ratio=round(ratio, 1),
                        )
                    )

            # -- filename deception ---------------------------------------
            bidi = has_bidi_deception(name)
            if bidi:
                findings.append(
                    _f(
                        "archive_bidi_filename",
                        "Entry name uses a right-to-left override",
                        "An entry's name contains an invisible character that makes "
                        "it display differently from what it really is.",
                        "This trick makes an executable look like a picture or a PDF "
                        "in the file listing. It is used for nothing else.",
                        "Do not open this archive. Send it to IT.",
                        Severity.HIGH,
                        Confidence.HIGH,
                        evidence=f"{prefix}{name!r} contains {bidi}"[:300],
                    )
                )
            else:
                invisible = has_invisible_chars(name)
                if invisible:
                    findings.append(
                        _f(
                            "archive_invisible_chars",
                            "Entry name contains invisible characters",
                            "An entry's name contains characters that do not display, "
                            "so the name you see is not the whole name.",
                            "Hidden characters are used to disguise a file's real "
                            "extension, though they also turn up in files copied from "
                            "web pages.",
                            "Treat the archive as untrusted until IT confirms it.",
                            Severity.MEDIUM,
                            Confidence.MEDIUM,
                            evidence=f"{prefix}{name!r} contains {invisible}"[:300],
                        )
                    )

            if "\x00" in name:
                findings.append(
                    _f(
                        "archive_nul_in_name",
                        "Entry name contains a NUL byte",
                        "An entry's name contains a byte that cannot legally appear "
                        "in a filename.",
                        "A NUL byte truncates the name for some programs but not "
                        "others, so two tools disagree about what the file is called. "
                        "That disagreement is the attack.",
                        "Do not open this archive. Send it to IT.",
                        Severity.HIGH,
                        Confidence.HIGH,
                        evidence=f"{prefix}{name!r}"[:300],
                    )
                )

            suffixes = suffix_chain(name)
            disguised = (
                len(suffixes) >= 2
                and suffixes[-1] in EXECUTABLE_SUFFIXES
                and suffixes[-2] in LURE_SUFFIXES
            )
            if disguised:
                findings.append(
                    _f(
                        "archive_double_extension",
                        "Entry is disguised with a double extension",
                        f"The archive contains a file named like a document but ending "
                        f"in {suffixes[-1]}, which the computer will run as a program.",
                        "Windows hides known extensions by default, so "
                        "'essay.pdf.exe' shows up as 'essay.pdf'. Double-clicking it "
                        "runs a program instead of opening a document.",
                        "Do not open this archive. Send it to IT.",
                        Severity.HIGH,
                        Confidence.HIGH,
                        evidence=f"{prefix}{name}"[:300],
                    )
                )
            elif suffixes and suffixes[-1] in EXECUTABLE_SUFFIXES:
                findings.append(
                    _f(
                        "archive_executable_member",
                        "Archive contains a runnable file",
                        f"The archive contains {Path(name).name}, which the computer "
                        f"treats as a program or script rather than a document.",
                        "Student coursework rarely needs to ship a runnable program. "
                        "When it does — a computing class, a game project — this is "
                        "expected; otherwise it is the most common way malware "
                        "arrives in a submission.",
                        "If this is not a programming assignment, do not open it. "
                        "If it is, open it in a text editor rather than running it.",
                        Severity.HIGH,
                        Confidence.MEDIUM
                        if _is_code_assignment_shaped(lowered)
                        else Confidence.HIGH,
                        evidence=f"{prefix}{name}"[:300],
                    )
                )

            # Collected regardless of depth: if we are too deep to open them,
            # that fact is itself reported below rather than silently dropped.
            if (
                Path(lowered).suffix in CONTAINER_SUFFIXES
                and info.file_size <= limits.max_nested_extract_bytes
                and not (info.flag_bits & 0x1)
            ):
                nested_candidates.append(info)

        # -- aggregate checks ---------------------------------------------
        if total_uncompressed > limits.max_total_uncompressed:
            findings.append(
                _f(
                    "archive_bomb_total",
                    "Archive unpacks to an unreasonable total size",
                    f"Unpacking this archive would produce about "
                    f"{_human(total_uncompressed)} of files.",
                    "An archive that unpacks to far more than it appears to contain "
                    "is the classic shape of a decompression bomb.",
                    "Do not extract this archive.",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    evidence=f"{_human(total_uncompressed)} declared uncompressed",
                    total_uncompressed=total_uncompressed,
                )
            )

        if not is_ooxml and depth == 0:
            nested_names = [
                i.filename
                for i in infolist
                if Path(i.filename.lower()).suffix in CONTAINER_SUFFIXES
            ]
            if nested_names:
                findings.append(
                    _f(
                        "archive_nested",
                        "Archive contains other archives",
                        f"This archive contains {len(nested_names)} further "
                        f"archive(s) inside it.",
                        "Nesting archives is a routine way to make automated scanners "
                        "give up before they reach the payload. It is also just how "
                        "some people package folders.",
                        "The scanner looked inside up to "
                        f"{limits.max_archive_depth} levels. Anything deeper was not "
                        "checked.",
                        Severity.LOW,
                        Confidence.HIGH,
                        evidence=", ".join(nested_names[:5])[:300],
                    )
                )

        # -- bounded recursion ---------------------------------------------
        if depth < limits.max_archive_depth:
            for info in nested_candidates[:16]:
                nested = _read_nested(archive, info, limits)
                if nested is None:
                    findings.append(
                        _f(
                            "archive_nested_unreadable",
                            "Nested archive could not be read",
                            f"An archive inside this archive ({Path(info.filename).name}) "
                            "could not be opened, so its contents were not checked.",
                            "Anything that could not be opened has not been cleared.",
                            "Treat the outer archive as unchecked.",
                            Severity.LOW,
                            Confidence.HIGH,
                            evidence=f"{prefix}{info.filename}"[:300],
                            incomplete=True,
                        )
                    )
                    continue
                findings.extend(
                    _rescope_nested(
                        analyze_archive(
                            io.BytesIO(nested),
                            limits=limits,
                            display_name=f"{prefix}{info.filename}",
                            depth=depth + 1,
                        )
                    )
                )
        elif nested_candidates:
            findings.append(
                _f(
                    "archive_depth_limit",
                    "Archive nesting exceeded the inspection depth",
                    f"Archives nested more than {limits.max_archive_depth} levels deep "
                    "were not opened.",
                    "Deeply nested archives are a way to hide from scanners. What was "
                    "not opened was not checked.",
                    "If this file matters, ask for it as loose files instead.",
                    Severity.LOW,
                    Confidence.HIGH,
                    evidence=f"depth {depth} at {prefix}",
                    incomplete=True,
                )
            )

    return findings[: limits.max_findings_per_file]


#: A nested archive that will not open says nothing about the outer archive's
#: own integrity, so its container-level codes are remapped on the way out.
_NESTED_REMAP = {
    "archive_corrupt": "archive_nested_unreadable",
    "archive_unreadable": "archive_nested_unreadable",
    "archive_directory_unreadable": "archive_nested_unreadable",
}


def _rescope_nested(findings: List[Finding]) -> List[Finding]:
    out: List[Finding] = []
    for finding in findings:
        mapped = _NESTED_REMAP.get(finding.code)
        if mapped is None:
            out.append(finding)
            continue
        out.append(
            _f(
                mapped,
                "Nested archive could not be read",
                "An archive stored inside this one could not be opened, so its "
                "contents were not checked.",
                "Anything that could not be opened has not been cleared. It is "
                "usually a damaged file, occasionally a deliberate one.",
                "Treat the outer archive as only partly checked.",
                Severity.LOW,
                Confidence.HIGH,
                evidence=finding.evidence,
                incomplete=True,
            )
        )
    return out


def _read_nested(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, limits: ScanLimits
) -> Optional[bytes]:
    """Read at most ``max_nested_extract_bytes`` of a member into memory.

    Never writes to disk and never trusts ``info.file_size``; the read itself is
    the bound.
    """
    try:
        with archive.open(info, "r") as member:
            data = member.read(limits.max_nested_extract_bytes + 1)
    except (RuntimeError, zipfile.BadZipFile, OSError, EOFError, NotImplementedError):
        return None
    if len(data) > limits.max_nested_extract_bytes:
        return None
    return data


def _is_code_assignment_shaped(lowered_name: str) -> bool:
    """Reduce confidence for runnable files that look like coursework."""
    return lowered_name.endswith((".js", ".sh", ".ps1")) and any(
        token in lowered_name for token in ("src/", "test", "assignment", "homework", "lab")
    )


def _human(num: int) -> str:
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:,.0f} {unit}" if unit == "B" else f"{value:,.1f} {unit}"
        value /= 1024
    return f"{num} B"


__all__ = ["analyze_archive"]
