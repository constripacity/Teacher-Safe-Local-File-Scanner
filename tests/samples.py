"""Harmless sample builders shared by the test suite.

Every sample built here is inert. The corpus reproduces the *structure* of a
risky file — an archive member that escapes its folder, a PNG with a ZIP glued
to the end, a document with a remote-template relationship — using payloads like
``echo "harmless"``. No malware ever enters this repository.
"""
from __future__ import annotations

import io
import struct
import zipfile
import zlib
from typing import Dict, Iterable, List, Tuple

HARMLESS = b'echo "harmless test payload"\n'

CONTENT_TYPES = (
    '<?xml version="1.0"?><Types '
    'xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
)
ROOT_RELS = (
    '<?xml version="1.0"?><Relationships '
    'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
)
DOC_XML = (
    '<?xml version="1.0"?><w:document '
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body><w:p><w:r><w:t>hello</w:t></w:r></w:p></w:body></w:document>"
)
EXTERNAL_TEMPLATE_RELS = (
    '<?xml version="1.0"?><Relationships '
    'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/attachedTemplate" Target="http://template.example.invalid/x.dotm" '
    'TargetMode="External"/></Relationships>'
)


def make_zip(
    entries: Iterable[Tuple[str, bytes]], compress: int = zipfile.ZIP_DEFLATED
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buf.getvalue()


def make_docx(extra: Dict[str, bytes] | None = None, body: str = DOC_XML) -> bytes:
    entries: List[Tuple[str, bytes]] = [
        ("[Content_Types].xml", CONTENT_TYPES.encode()),
        ("_rels/.rels", ROOT_RELS.encode()),
        ("word/document.xml", body.encode()),
        ("word/settings.xml", b"<w:settings/>"),
    ]
    entries.extend((k, v) for k, v in (extra or {}).items())
    return make_zip(entries, zipfile.ZIP_STORED)


def make_png(trailer: bytes = b"", chunks: bytes = b"") -> bytes:
    out = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    out += (
        struct.pack(">I", len(ihdr))
        + b"IHDR"
        + ihdr
        + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
    )
    out += chunks
    out += struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
    return out + trailer


def make_jpeg(trailer: bytes = b"") -> bytes:
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"\x00" * 64 + b"\xff\xd9" + trailer


def make_pdf(extra_catalog: str = "", trailer_extra: bytes = b"") -> bytes:
    return (
        "%PDF-1.5\n"
        f"1 0 obj\n<< /Type /Catalog {extra_catalog}>>\nendobj\n"
        "trailer\n<< /Root 1 0 R >>\n%%EOF\n"
    ).encode() + trailer_extra


def encrypted_flag_zip() -> bytes:
    """A ZIP whose entry is *marked* encrypted.

    The standard library cannot write encrypted entries, so general-purpose bit
    0 is set in both the local header and the central directory. The detector
    reads the flag, not the payload, so this exercises the real code path.
    """
    raw = bytearray(make_zip([("secret.txt", HARMLESS)], zipfile.ZIP_STORED))
    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    if local >= 0:
        raw[local + 6] |= 0x01
    if central >= 0:
        raw[central + 8] |= 0x01
    return bytes(raw)


def codes(findings) -> set:
    """Set of finding codes — the usual assertion target."""
    return {f.code for f in findings}
