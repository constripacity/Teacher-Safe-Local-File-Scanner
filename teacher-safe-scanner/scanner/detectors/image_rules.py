from typing import BinaryIO, Dict, List


def analyze_image(f: BinaryIO, strict: bool = False) -> List[Dict]:
    data = f.read()
    findings: List[Dict] = []
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        idx = data.rfind(b"IEND")
        if idx != -1 and len(data) > idx + 12:
            findings.append(
                {
                    "rule": "png_appended_data",
                    "severity": "medium",
                    "detail": "Data present after PNG IEND (appended payload).",
                }
            )
    if data.startswith(b"\xff\xd8\xff") and not data.endswith(b"\xff\xd9"):
        findings.append(
            {
                "rule": "jpeg_appended_data",
                "severity": "medium",
                "detail": "JPEG missing terminal marker; potential appended data.",
            }
        )
    if strict and b"Exif" in data and len(data) > 5_000_000:
        findings.append(
            {
                "rule": "image_large_exif",
                "severity": "low",
                "detail": "Large image with EXIF present (strict mode).",
            }
        )
    return findings
