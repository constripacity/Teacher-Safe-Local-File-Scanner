"""Office, PDF and image detectors."""
from __future__ import annotations

import io

import pytest

from scanner.detectors.image import analyze_image
from scanner.detectors.office import analyze_office
from scanner.detectors.pdf import analyze_pdf
from tests.samples import (
    DOC_XML,
    EXTERNAL_TEMPLATE_RELS,
    codes,
    make_docx,
    make_jpeg,
    make_pdf,
    make_png,
    make_zip,
)


# --------------------------------------------------------------------- office
def office(data: bytes, limits, suffix=".docx"):
    return analyze_office(io.BytesIO(data), limits=limits, suffix=suffix)


def test_ordinary_word_document_is_clean(limits):
    """Regression: the old detector flagged every .docx because every .docx
    contains word/settings.xml."""
    assert codes(office(make_docx(), limits)) == set()


def test_macro_project_is_detected(limits):
    findings = office(make_docx({"word/vbaProject.bin": b"\x00" * 64}), limits, ".docm")
    match = next(f for f in findings if f.code == "office_macro_present")
    assert match.severity.value == "high"
    assert match.confidence.value == "high"


def test_macro_enabled_extension_without_macros_is_only_informational(limits):
    findings = office(make_docx(), limits, ".docm")
    match = next(f for f in findings if f.code == "office_macro_extension_only")
    assert match.severity.value == "info"


def test_remote_template_relationship_is_detected(limits):
    data = make_docx({"word/_rels/settings.xml.rels": EXTERNAL_TEMPLATE_RELS.encode()})
    assert "office_external_attachedtemplate" in codes(office(data, limits))


def test_ordinary_hyperlink_is_not_flagged(limits):
    rels = (
        '<?xml version="1.0"?><Relationships '
        'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/'
        '2006/relationships/hyperlink" Target="https://example.org" TargetMode="External"/>'
        "</Relationships>"
    )
    data = make_docx({"word/_rels/document.xml.rels": rels.encode()})
    assert codes(office(data, limits)) == set()


def test_dde_field_is_detected(limits):
    body = DOC_XML.replace("<w:t>hello</w:t>", "<w:instrText>DDEAUTO calc.exe</w:instrText>")
    assert "office_dde_field" in codes(office(make_docx(body=body), limits))


def test_embedded_object_and_activex(limits):
    assert "office_embedded_object" in codes(
        office(make_docx({"word/embeddings/oleObject1.bin": b"\x00"}), limits)
    )
    assert "office_activex" in codes(
        office(make_docx({"word/activeX/activeX1.bin": b"\x00"}), limits)
    )


def test_program_renamed_to_docx(limits):
    assert "office_container_mismatch" in codes(office(b"MZ\x90\x00" + b"\x00" * 64, limits))


def test_legacy_ole_macro_storage(limits):
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 + b"V\x00B\x00A\x00" + b"\x00" * 64
    assert "office_legacy_macro" in codes(office(data, limits, ".doc"))


# ------------------------------------------------------------------------ pdf
def pdf(data: bytes, limits):
    return analyze_pdf(io.BytesIO(data), limits=limits, size=len(data))


def test_ordinary_pdf_is_clean(limits):
    assert codes(pdf(make_pdf(), limits)) == set()


def test_javascript_and_open_action(limits):
    found = codes(pdf(make_pdf("/OpenAction << /S /JavaScript /JS (x) >> "), limits))
    assert {"pdf_javascript", "pdf_open_action"} <= found


def test_javascript_fires_once_not_twice(limits):
    """/JS and /JavaScript are the same fact; the old scanner counted both."""
    findings = pdf(make_pdf("/OpenAction << /S /JavaScript /JS (x) >> "), limits)
    assert len([f for f in findings if f.code == "pdf_javascript"]) == 1


def test_launch_action_is_high_severity(limits):
    findings = pdf(make_pdf("/Launch (calc.exe) "), limits)
    match = next(f for f in findings if f.code == "pdf_launch_action")
    assert match.severity.value == "high"


def test_token_spanning_a_window_boundary_is_still_found(limits):
    """The original used a 10-byte overlap while searching 13-byte tokens."""
    filler = b"A" * (512 * 1024 - len(b"%PDF-1.4\n") - 6)
    data = b"%PDF-1.4\n" + filler + b"/Launc" + b"h (x)\n%%EOF\n"
    assert "pdf_launch_action" in codes(pdf(data, limits))


def test_appended_payload_after_eof(limits):
    data = make_pdf(trailer_extra=b"PK\x03\x04" + b"A" * 4096)
    assert "pdf_appended_data" in codes(pdf(data, limits))


def test_prefix_before_pdf_header(limits):
    assert "pdf_header_offset" in codes(pdf(b"GIF89a" + b"\x00" * 40 + make_pdf(), limits))


def test_encrypted_pdf_marks_inspection_incomplete(limits):
    findings = pdf(make_pdf().replace(b"trailer", b"trailer /Encrypt 5 0 R "), limits)
    assert next(f for f in findings if f.code == "pdf_encrypted").inspection_incomplete


# ---------------------------------------------------------------------- image
def image(data: bytes, limits, suffix=".png"):
    return analyze_image(io.BytesIO(data), limits=limits, size=len(data), suffix=suffix)


def test_ordinary_image_is_clean(limits):
    assert codes(image(make_png(), limits)) == set()
    assert codes(image(make_jpeg(), limits, ".jpg")) == set()


def test_polyglot_zip_inside_png(limits):
    data = make_png(trailer=make_zip([("hidden.txt", b"payload")]))
    match = next(f for f in image(data, limits) if f.code == "image_polyglot")
    assert match.severity.value == "high"


def test_large_appended_payload_is_detected(limits):
    """The original only read the last 8 KB, so a 2 MB payload passed as clean."""
    data = make_png(trailer=b"Q" * (2 * 1024 * 1024))
    assert "image_large_appended_data" in codes(image(data, limits))


def test_moderate_appended_payload_is_detected(limits):
    assert "image_appended_data" in codes(image(make_png(trailer=b"Q" * 40_000), limits))


def test_tiny_trailer_is_only_informational(limits):
    findings = image(make_png(trailer=b"q" * 40), limits)
    match = next(f for f in findings if f.code == "image_small_trailer")
    assert match.severity.value == "info"


def test_program_renamed_to_jpg(limits):
    match = next(
        f for f in image(b"MZ\x90\x00" + b"\x00" * 512, limits, ".jpg")
        if f.code == "image_not_an_image"
    )
    assert match.severity.value == "high"


def test_impossible_chunk_length(limits):
    import struct

    bad = struct.pack(">I", 2**31) + b"tEXt" + b"x" * 4
    assert "image_bad_chunk_length" in codes(image(make_png(chunks=bad), limits))


@pytest.mark.parametrize("suffix", [".png", ".jpg"])
def test_every_finding_has_teacher_facing_text(limits, suffix):
    data = make_png(trailer=b"PK\x03\x04" + b"Z" * 4000)
    for finding in image(data, limits, suffix):
        assert finding.plain and finding.why and finding.action
        assert finding.detector
