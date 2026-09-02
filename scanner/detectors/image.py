"""Static inspection of image files.

Images are never decoded. Only container structure is examined, because
decoding an attacker-controlled image is itself one of the risks this tool
exists to avoid.
"""
from __future__ import annotations

import logging
from typing import BinaryIO, List, Optional

from ..findings import Confidence, Finding, Severity
from ..limits import ScanLimits
from .base import read_head, read_tail, sniff_magic

LOGGER = logging.getLogger(__name__)

DETECTOR = "image"

#: Sentinels returned by :func:`_trailing_bytes` when the image terminator was
#: not located. Both mean "there is more here than an image", not "clean".
TERMINATOR_MISSING = -1
TERMINATOR_TOO_FAR = -2

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"
GIF_MAGICS = (b"GIF87a", b"GIF89a")

#: Byte sequences that should never appear after an image's terminator.
POLYGLOT_MARKERS = {
    b"PK\x03\x04": "a ZIP archive",
    b"MZ": "a Windows program",
    b"%PDF-": "a PDF document",
    b"Rar!\x1a\x07": "a RAR archive",
    b"7z\xbc\xaf\x27\x1c": "a 7-Zip archive",
    b"<?php": "PHP source code",
    b"<script": "a script tag",
    b"#!/": "a shell script",
}


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


def analyze_image(
    handle: BinaryIO, *, limits: ScanLimits, size: Optional[int] = None, suffix: str = ""
) -> List[Finding]:
    findings: List[Finding] = []
    head = read_head(handle, 64)
    if size is None:
        handle.seek(0, 2)
        size = handle.tell()

    kind = sniff_magic(head)
    if suffix in {".png", ".jpg", ".jpeg", ".gif"} and kind not in {"png", "jpeg", "gif"}:
        findings.append(
            _f(
                "image_not_an_image",
                "File is not the picture it claims to be",
                f"This file is named like an image ({suffix}) but its contents are "
                f"not image data — they look like {_describe(kind)}.",
                "Renaming a program to end in .jpg is the oldest trick there is. "
                "Some programs open files by content rather than by name, so the "
                "real type is what matters.",
                "Do not open it. Send it to IT.",
                Severity.HIGH,
                Confidence.HIGH,
                evidence=f"magic bytes {head[:8]!r} detected as {kind}",
            )
        )
        return findings

    trailing = _trailing_bytes(handle, kind, limits, size)
    if trailing is not None:
        count, snippet = trailing
        if count == TERMINATOR_TOO_FAR:
            findings.append(
                _f(
                    "image_large_appended_data",
                    "A large amount of data is stored after the picture",
                    "The end of the picture data is more than "
                    f"{limits.tail_bytes // 1024} KB from the end of the file, so "
                    "this file carries a substantial amount of something else.",
                    "Image viewers stop at the end of the picture. Hundreds of "
                    "kilobytes of invisible trailing content is not something a "
                    "camera or an editor produces.",
                    "Do not open this file. Send it to IT.",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    evidence=f"no {kind} terminator within the last {limits.tail_bytes} bytes",
                )
            )
        elif count == TERMINATOR_MISSING:
            findings.append(
                _f(
                    "image_truncated",
                    "Picture is incomplete",
                    "This picture has no end marker anywhere in the file, so it is "
                    "truncated or is not really this kind of image.",
                    "An incomplete image usually means a failed upload. It also "
                    "means the file could not be checked as an image.",
                    "Ask the student to re-send it.",
                    Severity.LOW,
                    Confidence.MEDIUM,
                    evidence=f"no {kind} terminator found in {size} bytes",
                    incomplete=True,
                )
            )
        elif count > 0:
            polyglot = _identify_polyglot(snippet)
            if polyglot:
                findings.append(
                    _f(
                        "image_polyglot",
                        "Another file is hidden inside this image",
                        f"After the picture data ends, this file contains {polyglot}.",
                        "One file that is both a picture and an archive opens as a "
                        "picture for you and as an archive for whatever the attacker "
                        "points at it. Nothing legitimate produces this.",
                        "Do not open this file. Send it to IT.",
                        Severity.HIGH,
                        Confidence.HIGH,
                        evidence=f"{count:,} trailing bytes beginning {snippet[:16]!r}",
                    )
                )
            elif count > 1024:
                findings.append(
                    _f(
                        "image_appended_data",
                        "Extra data is stored after the end of the picture",
                        f"There are {count:,} bytes of unknown content after the "
                        "picture data ends.",
                        "Image viewers stop at the end of the picture, so trailing "
                        "data is invisible. Some cameras and editors legitimately "
                        "append small blocks, but this much is unusual.",
                        "Treat the file as untrusted until IT looks at it.",
                        Severity.MEDIUM,
                        Confidence.MEDIUM,
                        evidence=f"{count:,} trailing bytes beginning {snippet[:16]!r}",
                    )
                )
            else:
                findings.append(
                    _f(
                        "image_small_trailer",
                        "Small amount of data after the picture",
                        f"There are {count} bytes after the picture data ends.",
                        "Small trailers are produced routinely by phone cameras and "
                        "editing software. On its own this means very little.",
                        "No action needed unless something else was also found.",
                        Severity.INFO,
                        Confidence.MEDIUM,
                        evidence=f"{count} trailing bytes",
                    )
                )

    if kind == "png" and size > 0:
        findings.extend(_png_structure(handle, limits, size))

    return findings[: limits.max_findings_per_file]


def _trailing_bytes(
    handle: BinaryIO, kind: str, limits: ScanLimits, size: int
) -> Optional[tuple[int, bytes]]:
    """Return ``(trailing_count, first_trailing_bytes)`` or ``None``.

    The original implementation only read the last 8 KB and looked for the
    terminator there — which meant a 1 MB appended payload made the terminator
    fall outside the window and the check silently passed. This version searches
    from the end backwards in growing windows so large trailers are exactly the
    case it catches.
    """
    terminator = {"png": b"IEND", "jpeg": b"\xff\xd9"}.get(kind)
    if terminator is None:
        return None

    # Search backwards in growing windows until the terminator is found or the
    # whole file has been covered. The bound is ScanLimits.tail_bytes, and the
    # window is clamped to the file size so small files are searched too — the
    # original code's ``window <= size`` guard skipped them entirely.
    window = min(64 * 1024, size)
    while True:
        tail = read_tail(handle, window, size=size)
        index = tail.rfind(terminator)
        if index >= 0:
            # PNG: IEND is followed by a 4-byte CRC. JPEG: EOI is the last 2 bytes.
            end_offset = size - len(tail) + index + (8 if kind == "png" else 2)
            trailing_count = max(size - end_offset, 0)
            handle.seek(end_offset)
            return trailing_count, handle.read(64)
        if window >= size:
            # Whole file searched and no terminator: the image is truncated.
            return TERMINATOR_MISSING, b""
        if window >= limits.tail_bytes:
            # The terminator is further from the end than we are willing to
            # read, which means there is at least ``tail_bytes`` of trailing
            # content. That is itself the finding — returning None here (as the
            # original did) would report a large appended payload as clean.
            return TERMINATOR_TOO_FAR, b""
        window = min(window * 4, size, limits.tail_bytes)


def _identify_polyglot(snippet: bytes) -> Optional[str]:
    for marker, label in POLYGLOT_MARKERS.items():
        if snippet.startswith(marker) or marker in snippet[:64]:
            return label
    return None


def _png_structure(handle: BinaryIO, limits: ScanLimits, size: int) -> List[Finding]:
    """Walk the PNG chunk list, bounded, looking for oversized ancillary chunks."""
    findings: List[Finding] = []
    handle.seek(len(PNG_MAGIC))
    consumed = len(PNG_MAGIC)
    chunks = 0
    while consumed + 8 <= size and chunks < 4096:
        header = handle.read(8)
        if len(header) < 8:
            break
        length = int.from_bytes(header[:4], "big")
        ctype = header[4:8]
        if length > size:
            findings.append(
                _f(
                    "image_bad_chunk_length",
                    "Picture contains an impossible internal size",
                    "One of the picture's internal blocks claims to be larger than "
                    "the whole file.",
                    "Malformed structure fields are how image parsers are made to "
                    "read past the end of their buffers.",
                    "Do not open this file in an image editor. Send it to IT.",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    evidence=f"chunk {ctype!r} declares {length} bytes in a {size}-byte file",
                )
            )
            break
        if ctype in (b"tEXt", b"zTXt", b"iTXt", b"eXIf") and length > 512 * 1024:
            findings.append(
                _f(
                    "image_large_metadata",
                    "Picture carries an unusually large hidden text block",
                    f"A metadata block inside this picture holds "
                    f"{length / 1024:,.0f} KB of text.",
                    "Metadata blocks are meant for captions and camera settings. "
                    "Very large ones are a place to store something that is not "
                    "metadata.",
                    "Treat the file as untrusted until IT looks at it.",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    evidence=f"{ctype.decode('ascii', 'replace')} chunk of {length} bytes",
                )
            )
        if ctype == b"IEND":
            break
        try:
            handle.seek(length + 4, 1)
        except OSError:  # pragma: no cover
            break
        consumed += 8 + length + 4
        chunks += 1
    return findings


def _describe(kind: str) -> str:
    return {
        "pe": "a Windows program",
        "elf": "a Linux program",
        "macho": "a macOS program",
        "macho-fat": "a macOS program",
        "zip": "a ZIP archive",
        "pdf": "a PDF document",
        "ole": "an old-format Office document",
        "script": "a script",
        "rar": "a RAR archive",
        "unknown": "something the scanner does not recognise",
    }.get(kind, kind)


__all__ = ["analyze_image"]
