"""Shared, bounded primitives for every detector.

Two rules hold everywhere in this package:

1. **Nothing is executed.** No macro is run, no PDF is rendered, no archive is
   extracted to a path the operating system might act on.
2. **Nothing is unbounded.** Every read is capped by :class:`~scanner.limits.ScanLimits`.
   Detectors receive an open binary handle and are expected to stream.
"""
from __future__ import annotations

import logging
import re
import unicodedata
from pathlib import Path
from typing import BinaryIO, Iterator, Optional

from ..limits import ScanLimits

LOGGER = logging.getLogger(__name__)


#: Magic-byte signatures -> canonical short type name.
#: Longest signatures are checked first so ``PK\x03\x04`` does not shadow OOXML.
MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"%PDF-", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),  # legacy .doc/.xls/.ppt/.msi
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x7fELF", "elf"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"MZ", "pe"),
    (b"{\\rtf", "rtf"),
    (b"<?xml", "xml"),
    (b"#!", "script"),
]

#: Which magic types are acceptable for a given file extension. Used for the
#: extension/content mismatch detector. ``None`` means "we have no opinion".
EXTENSION_EXPECTATIONS: dict[str, set[str]] = {
    ".pdf": {"pdf"},
    ".png": {"png"},
    ".jpg": {"jpeg"},
    ".jpeg": {"jpeg"},
    ".gif": {"gif"},
    ".zip": {"zip"},
    ".docx": {"zip"},
    ".xlsx": {"zip"},
    ".pptx": {"zip"},
    ".docm": {"zip"},
    ".xlsm": {"zip"},
    ".pptm": {"zip"},
    ".odt": {"zip"},
    ".ods": {"zip"},
    ".odp": {"zip"},
    ".doc": {"ole"},
    ".xls": {"ole"},
    ".ppt": {"ole"},
    ".rar": {"rar"},
    ".7z": {"7z"},
    ".gz": {"gzip"},
    ".rtf": {"rtf"},
}

#: Extensions the operating system may execute or interpret on double-click.
EXECUTABLE_SUFFIXES: frozenset[str] = frozenset(
    {
        ".exe", ".com", ".scr", ".pif", ".cpl", ".msi", ".msp", ".dll", ".sys",
        ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
        ".wsh", ".hta", ".jar", ".app", ".command", ".sh", ".bash", ".zsh",
        ".lnk", ".url", ".reg", ".inf", ".scf", ".chm", ".apk", ".dmg", ".pkg",
    }
)

#: Extensions that commonly appear as the *first* half of a disguise, e.g.
#: ``essay.pdf.exe``.
LURE_SUFFIXES: frozenset[str] = frozenset(
    {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".png",
     ".jpg", ".jpeg", ".gif", ".mp4", ".mp3", ".csv", ".rtf"}
)

#: Bidirectional-override and other invisible characters used to reverse a
#: filename's apparent extension (``essay\u202Egpj.exe`` renders as
#: ``essayexe.jpg``).
BIDI_CONTROL_CHARS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
    "\u200e", "\u200f",
}

ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff"}

URL_RE = re.compile(rb"https?://[^\s\"'<>)\]}\x00]{4,400}")


def sniff_magic(head: bytes) -> str:
    """Return a canonical type name for *head*, or ``"unknown"``."""
    for signature, label in MAGIC_SIGNATURES:
        if head.startswith(signature):
            return label
    if head[:4] == b"\x00\x00\x01\x00":
        return "ico"
    return "unknown"


def read_head(handle: BinaryIO, nbytes: int) -> bytes:
    handle.seek(0)
    return handle.read(nbytes)


def read_tail(handle: BinaryIO, nbytes: int, *, size: Optional[int] = None) -> bytes:
    if size is None:
        handle.seek(0, 2)
        size = handle.tell()
    offset = max(size - nbytes, 0)
    handle.seek(offset)
    return handle.read(nbytes)


def iter_windows(
    handle: BinaryIO,
    *,
    limits: ScanLimits,
    window: int = 256 * 1024,
    overlap: int = 64,
) -> Iterator[tuple[int, bytes]]:
    """Yield ``(offset, chunk)`` windows that overlap by *overlap* bytes.

    The original PDF scanner used a 10-byte overlap while searching for a
    13-byte token, so tokens straddling a chunk boundary were silently missed.
    *overlap* must be at least ``len(longest_token) - 1``; callers pass it
    explicitly and this function enforces the invariant.
    """
    if overlap < 0:
        raise ValueError("overlap must be non-negative")
    if window <= overlap:
        raise ValueError("window must be larger than overlap")

    handle.seek(0)
    consumed = 0
    carry = b""
    carry_offset = 0
    while consumed < limits.max_read_bytes:
        to_read = min(window - len(carry), limits.max_read_bytes - consumed)
        if to_read <= 0:
            break
        chunk = handle.read(to_read)
        if not chunk:
            break
        consumed += len(chunk)
        buffer = carry + chunk
        yield carry_offset, buffer
        if len(buffer) <= overlap:
            carry = buffer
            carry_offset = carry_offset
        else:
            carry = buffer[-overlap:]
            carry_offset = carry_offset + len(buffer) - overlap


def suffix_chain(name: str) -> list[str]:
    """Lower-cased suffix list, ignoring version-ish numeric fragments.

    ``Path("report.v2.final.docx").suffixes`` yields ``['.v2', '.final', '.docx']``
    which produces useless "double extension" alarms. We keep only suffixes that
    look like real extensions (alphanumeric, 1-5 chars, not purely numeric).
    """
    parts = Path(name).suffixes
    kept: list[str] = []
    for part in parts:
        body = part[1:]
        if not body or len(body) > 5:
            continue
        if body.isdigit():
            continue
        if not body.isalnum():
            continue
        kept.append(part.lower())
    return kept


def has_bidi_deception(name: str) -> Optional[str]:
    """Return the offending character name if *name* contains a bidi override."""
    for char in name:
        if char in BIDI_CONTROL_CHARS:
            return unicodedata.name(char, repr(char))
    return None


def has_invisible_chars(name: str) -> Optional[str]:
    for char in name:
        if char in ZERO_WIDTH_CHARS:
            return unicodedata.name(char, repr(char))
        if unicodedata.category(char) == "Cf" and char not in BIDI_CONTROL_CHARS:
            return unicodedata.name(char, repr(char))
    return None


def looks_like_path_escape(member_name: str) -> bool:
    """True when an archive member would write outside the extraction root.

    Covers ``../`` traversal, absolute POSIX paths, Windows drive letters and
    UNC paths, and backslash separators that Python's zipfile does not normalise.
    """
    name = member_name.replace("\\", "/")
    if name.startswith("/"):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", member_name):
        return True
    if member_name.startswith("\\\\"):
        return True
    parts = [p for p in name.split("/") if p not in ("", ".")]
    depth = 0
    for part in parts:
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


__all__ = [
    "MAGIC_SIGNATURES",
    "EXTENSION_EXPECTATIONS",
    "EXECUTABLE_SUFFIXES",
    "LURE_SUFFIXES",
    "URL_RE",
    "sniff_magic",
    "read_head",
    "read_tail",
    "iter_windows",
    "suffix_chain",
    "has_bidi_deception",
    "has_invisible_chars",
    "looks_like_path_escape",
]
