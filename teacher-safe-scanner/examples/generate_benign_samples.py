"""Utility script to generate benign sample files for demonstrations.

This script avoids storing binary fixtures directly in the repository to
keep pull requests text-only while still providing realistic sample files
for scanner demonstrations and tests.
"""
from __future__ import annotations

import base64
import zipfile
from pathlib import Path

SAMPLE_DIR = Path(__file__).parent / "benign_samples"

PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=="
)


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def create_sample_image(path: Path) -> None:
    if path.exists():
        return
    data = base64.b64decode(PNG_BASE64)
    path.write_bytes(data)


def create_sample_text(path: Path) -> None:
    if path.exists():
        return
    path.write_text(
        "This is a harmless plain text file used to validate the teacher-safe scanner.\n",
        encoding="utf-8",
    )


def create_sample_docx(path: Path) -> None:
    if path.exists():
        return
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            "[Content_Types].xml",
            (
                "<?xml version='1.0' encoding='UTF-8'?>\n"
                "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'>\n"
                "  <Default Extension='rels' "
                "ContentType='application/vnd.openxmlformats-package.relationships+xml'/>\n"
                "  <Default Extension='xml' ContentType='application/xml'/>\n"
                "  <Override PartName='/word/document.xml' "
                "ContentType='application/vnd.openxmlformats-officedocument/"
                "wordprocessingml.document.main+xml'/>\n"
                "</Types>\n"
            ),
        )
        zf.writestr(
            "_rels/.rels",
            (
                "<?xml version='1.0' encoding='UTF-8'?>\n"
                "<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'>\n"
                "  <Relationship Id='R1' "
                "Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
                "officeDocument' "
                "Target='word/document.xml'/>\n"
                "</Relationships>\n"
            ),
        )
        zf.writestr(
            "docProps/app.xml",
            (
                "<?xml version='1.0' encoding='UTF-8'?>\n"
                "<Properties xmlns='http://schemas.openxmlformats.org/officeDocument/2006/"
                "extended-properties' "
                "xmlns:vt='http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes'>\n"
                "  <Application>Teacher Safe Scanner</Application>\n"
                "</Properties>\n"
            ),
        )
        zf.writestr(
            "docProps/core.xml",
            (
                "<?xml version='1.0' encoding='UTF-8'?>\n"
                "<cp:coreProperties xmlns:cp='http://schemas.openxmlformats.org/package/2006/"
                "metadata/core-properties' "
                "xmlns:dc='http://purl.org/dc/elements/1.1/' xmlns:dcterms='http://purl.org/dc/terms/'>\n"
                "  <dc:title>Harmless Example</dc:title>\n"
                "</cp:coreProperties>\n"
            ),
        )
        zf.writestr(
            "word/document.xml",
            (
                "<?xml version='1.0' encoding='UTF-8'?>\n"
                "<w:document xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'>\n"
                "  <w:body>\n"
                "    <w:p>\n"
                "      <w:r>\n"
                "        <w:t>This document is a benign placeholder with no macros.</w:t>\n"
                "      </w:r>\n"
                "    </w:p>\n"
                "  </w:body>\n"
                "</w:document>\n"
            ),
        )


def main() -> None:
    ensure_directory(SAMPLE_DIR)
    create_sample_text(SAMPLE_DIR / "sample_text.txt")
    create_sample_image(SAMPLE_DIR / "sample_image.png")
    create_sample_docx(SAMPLE_DIR / "sample_docx.docx")


if __name__ == "__main__":
    main()
