from pathlib import Path

def write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def make_pdf_with_js(path: Path) -> None:
    """Create a minimal PDF payload that includes risky tokens."""
    write_file(
        path,
        b"%PDF-1.4\n1 0 obj\n<< /OpenAction 2 0 R /JavaScript 3 0 R >>\nendobj\n%%EOF",
    )

def make_zip_with_double_ext(path: Path) -> None:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("homework.png.exe", b"fake")
        archive.writestr("notes.txt", b"ok")
    path.write_bytes(buffer.getvalue())

def make_office_with_vba(path: Path) -> None:
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("word/vbaProject.bin", b"macro")
    path.write_bytes(buffer.getvalue())

def make_png_with_appended(path: Path) -> None:
    data = b"\x89PNG\r\n\x1a\n...IEND" + b"x" * 20
    write_file(path, data)
