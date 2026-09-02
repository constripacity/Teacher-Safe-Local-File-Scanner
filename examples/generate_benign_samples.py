#!/usr/bin/env python3
"""Generate a benign corpus that exercises every detector.

None of these files is malware. Every one is a harmless file that has been given
the *structure* a risky file would have: an archive whose member name escapes its
folder, a PNG with a ZIP appended, a .docx with a remote-template relationship
pointing at ``example.invalid``. The payloads are text like
``echo "this is a harmless sample"``.

This corpus is the project's demo, its regression suite, and the thing you show
someone who asks "does it actually detect anything?".

    python examples/generate_benign_samples.py            # writes examples/benign_samples
    python examples/generate_benign_samples.py --out /tmp/x
"""
from __future__ import annotations

import argparse
import io
import struct
import zipfile
import zlib
from pathlib import Path
from typing import Callable, Dict, List, Tuple

HARMLESS = b'echo "this is a harmless sample from the Teacher-Safe test corpus"\n'

CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="xml" ContentType="application/xml"/>'
    "</Types>"
)
ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" '
    'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    'Target="word/document.xml"/></Relationships>'
)
DOC_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:body><w:p><w:r><w:t>Harmless sample document.</w:t></w:r></w:p></w:body>"
    "</w:document>"
)


# --------------------------------------------------------------------------
def _png(trailer: bytes = b"", chunks: bytes = b"") -> bytes:
    out = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    out += struct.pack(">I", len(ihdr)) + b"IHDR" + ihdr
    out += struct.pack(">I", zlib.crc32(b"IHDR" + ihdr))
    pixel = zlib.compress(b"\x00\xff\xff\xff")
    out += struct.pack(">I", len(pixel)) + b"IDAT" + pixel
    out += struct.pack(">I", zlib.crc32(b"IDAT" + pixel))
    out += chunks
    out += struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
    return out + trailer


def _jpeg(trailer: bytes = b"") -> bytes:
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + (
        b"\xff\xdb\x00C\x00" + bytes(range(1, 65))
    ) + b"\xff\xd9" + trailer


def _zip(entries: List[Tuple[str, bytes]], compress: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buf.getvalue()


def _docx(extra: Dict[str, bytes] | None = None, body: str = DOC_XML) -> bytes:
    entries: List[Tuple[str, bytes]] = [
        ("[Content_Types].xml", CONTENT_TYPES.encode()),
        ("_rels/.rels", ROOT_RELS.encode()),
        ("word/document.xml", body.encode()),
        ("word/settings.xml", b"<w:settings/>"),
    ]
    entries.extend((k, v) for k, v in (extra or {}).items())
    return _zip(entries, zipfile.ZIP_STORED)


def _pdf(extra_catalog: str = "", trailer_extra: bytes = b"") -> bytes:
    body = (
        "%PDF-1.5\n"
        f"1 0 obj\n<< /Type /Catalog /Pages 2 0 R {extra_catalog}>>\nendobj\n"
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n"
        "trailer\n<< /Root 1 0 R /Size 4 >>\n%%EOF\n"
    ).encode()
    return body + trailer_extra


# --------------------------------------------------------------------------
#: name -> (builder, one-line description of what it is meant to trigger)
SAMPLES: Dict[str, Tuple[Callable[[], bytes], str]] = {
    # --- files that should come back clean -------------------------------
    "clean_essay.txt": (
        lambda: b"My essay about the water cycle.\nSee https://en.wikipedia.org/wiki/Water_cycle\n",
        "clean text file with an ordinary link",
    ),
    "clean_report.docx": (lambda: _docx(), "ordinary Word document, no macros"),
    "clean_diagram.png": (lambda: _png(), "ordinary PNG"),
    "clean_photo.jpg": (lambda: _jpeg(), "ordinary JPEG"),
    "clean_worksheet.pdf": (lambda: _pdf(), "ordinary PDF"),
    "clean_homework.zip": (
        lambda: _zip([("essay.txt", b"my essay"), ("notes/refs.txt", b"sources")]),
        "ordinary archive of coursework",
    ),
    # --- archives ---------------------------------------------------------
    "archive_path_traversal.zip": (
        lambda: _zip([("../../autorun.txt", HARMLESS), ("readme.txt", b"hi")]),
        "member escapes the extraction folder",
    ),
    "archive_with_program.zip": (
        lambda: _zip([("essay.txt", b"essay"), ("installer.exe", b"MZ" + HARMLESS)]),
        "archive containing a runnable file",
    ),
    "archive_double_extension.zip": (
        lambda: _zip([("Assignment.pdf.exe", b"MZ" + HARMLESS)]),
        "member disguised with a double extension",
    ),
    "archive_nested_deep.zip": (
        lambda: _zip([("level1.zip", _zip([("level2.zip", _zip([("deep.txt", b"x")]))]))]),
        "archives nested three levels deep",
    ),
    "archive_zip_bomb_shape.zip": (
        lambda: _zip([("expands.bin", b"\x00" * (48 * 1024 * 1024))]),
        "tiny archive that unpacks 48 MB (bomb ratio)",
    ),
    # --- office -----------------------------------------------------------
    "office_with_macro.docm": (
        lambda: _docx({"word/vbaProject.bin": b"\x00" * 512}),
        "document containing a macro project",
    ),
    "office_remote_template.docx": (
        lambda: _docx(
            {
                "word/_rels/settings.xml.rels": (
                    '<?xml version="1.0"?><Relationships '
                    'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    '<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/'
                    'officeDocument/2006/relationships/attachedTemplate" '
                    'Target="http://template.example.invalid/x.dotm" '
                    'TargetMode="External"/></Relationships>'
                ).encode()
            }
        ),
        "document that loads a template from the internet",
    ),
    "office_dde_field.docx": (
        lambda: _docx(
            body=DOC_XML.replace(
                "<w:t>Harmless sample document.</w:t>",
                "<w:instrText>DDEAUTO c:\\\\Windows\\\\System32\\\\calc.exe</w:instrText>",
            )
        ),
        "document containing a DDE field",
    ),
    "office_embedded_object.docx": (
        lambda: _docx({"word/embeddings/oleObject1.bin": b"\x00" * 128}),
        "document with an embedded object",
    ),
    "office_renamed_program.docx": (
        lambda: b"MZ\x90\x00" + HARMLESS + b"\x00" * 256,
        "program renamed to look like a Word file",
    ),
    # --- pdf --------------------------------------------------------------
    "pdf_javascript.pdf": (
        lambda: _pdf("/OpenAction << /S /JavaScript /JS (app.alert\\(1\\);) >> "),
        "PDF that runs JavaScript on open",
    ),
    "pdf_launch_action.pdf": (
        lambda: _pdf("/OpenAction << /S /Launch /F (calc.exe) >> "),
        "PDF that tries to launch a program",
    ),
    "pdf_appended_payload.pdf": (
        lambda: _pdf(trailer_extra=b"PK\x03\x04" + b"A" * 4096),
        "PDF with a ZIP appended after %%EOF",
    ),
    # --- images -----------------------------------------------------------
    "image_polyglot.png": (
        lambda: _png(trailer=_zip([("hidden.txt", HARMLESS)])),
        "PNG with a real ZIP hidden after IEND",
    ),
    "image_large_appended.jpg": (
        lambda: _jpeg(trailer=b"Q" * (600 * 1024)),
        "JPEG with 600 KB appended after the end marker",
    ),
    "image_is_really_a_program.jpg": (
        lambda: b"MZ\x90\x00" + HARMLESS + b"\x00" * 512,
        "program renamed to .jpg",
    ),
    # --- naming tricks ----------------------------------------------------
    "Assignment.pdf.exe": (lambda: b"MZ" + HARMLESS, "double extension on disk"),
    "invoice\u202egpj.exe": (
        lambda: b"MZ" + HARMLESS,
        "right-to-left override in the filename",
    ),
    # --- text -------------------------------------------------------------
    "links_suspicious.txt": (
        lambda: (
            b"Sources for my project:\n"
            b"https://bit.ly/3xAmPle\n"
            b"http://203.0.113.42/download\n"
            b"https://xn--80ak6aa92e.example/login\n"
        ),
        "text containing shortened, raw-IP and punycode links",
    ),
    # --- formats with no detector ------------------------------------------
    "coursework.7z": (
        lambda: b"7z\xbc\xaf\x27\x1c" + HARMLESS * 4,
        "7-Zip archive the scanner cannot open (reported as unchecked, not safe)",
    ),
    "essay.rtf": (
        lambda: b"{\\rtf1\\ansi A perfectly ordinary RTF document.}",
        "RTF document the scanner cannot parse (reported as unchecked, not safe)",
    ),
    # --- inspection-limited ------------------------------------------------
    "archive_password_protected.zip": (
        lambda: _encrypted_flag_zip(),
        "archive marked as password protected (cannot be inspected)",
    ),
    "broken_upload.zip": (
        lambda: b"PK\x03\x04" + b"corrupted-partial-upload" * 8,
        "truncated/corrupt archive",
    ),
    "empty_submission.docx": (lambda: b"", "zero-byte file"),
}


def _encrypted_flag_zip() -> bytes:
    """Produce a ZIP whose entry is *marked* encrypted.

    The stdlib cannot write encrypted entries, so we set general-purpose bit 0
    in both the local header and the central directory. The scanner reads the
    flag, not the payload, so this exercises the real code path.
    """
    raw = bytearray(_zip([("secret_notes.txt", HARMLESS)], zipfile.ZIP_STORED))
    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    if local >= 0:
        raw[local + 6] |= 0x01
    if central >= 0:
        raw[central + 8] |= 0x01
    return bytes(raw)


def write_samples(out_dir: Path) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    manifest: List[str] = [
        "# Benign test corpus",
        "",
        "Every file here is harmless. Each one reproduces the *structure* of a risky",
        "file so the detectors can be exercised without distributing malware.",
        "",
        "| file | what it is meant to trigger |",
        "| --- | --- |",
    ]
    for name, (builder, description) in sorted(SAMPLES.items()):
        path = out_dir / name
        path.write_bytes(builder())
        written.append(path)
        manifest.append(f"| `{name}` | {description} |")
    (out_dir / "README.md").write_text("\n".join(manifest) + "\n", encoding="utf-8")
    return written


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "benign_samples",
        help="directory to write the corpus into",
    )
    args = parser.parse_args(argv)
    written = write_samples(args.out)
    print(f"Wrote {len(written)} benign sample files to {args.out}")
    print("Now run:  python -m scanner scan", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
