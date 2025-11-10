from scanner import detectors


def test_detect_double_extension(tmp_path):
    path = tmp_path / "essay.pdf.exe"
    path.write_bytes(b"MZ")
    issue = detectors.detect_double_extension(path)
    assert issue and issue["code"] == "double_extension"


def test_detect_pdf_risks(tmp_path):
    path = tmp_path / "test.pdf"
    path.write_bytes(b"%PDF-1.4 /JavaScript")
    findings = detectors.detect_pdf_risks(path)
    assert any(f["code"] == "pdf_token" for f in findings)


def test_detect_zip_contents_flags_macro(tmp_path):
    import zipfile

    path = tmp_path / "doc.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("word/vbaProject.bin", b"dummy")
        zf.writestr("payload.exe", b"MZ")
    findings = detectors.detect_zip_contents(path)
    codes = {finding["code"] for finding in findings}
    assert "exe_in_zip" in codes
    assert "zip_vba_project" in codes


def test_extract_urls_and_flag(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("Visit http://xn--example.com for details", encoding="utf-8")
    findings = detectors.extract_urls_and_flag(path)
    assert findings
    assert findings[0]["code"] in {"url", "url_suspicious"}
