from typing import BinaryIO, Dict, List
import zipfile
import io
import os


SUSP_EXT = {".exe", ".dll", ".js", ".vbs", ".bat", ".cmd", ".scr", ".ps1", ".jar"}


def _double_ext(name: str) -> bool:
    base = os.path.basename(name)
    parts = base.split(".")
    return (
        len(parts) >= 3
        and parts[-1] not in ("zip", "rar", "7z", "gz")
        and parts[-2] in {"jpg", "png", "pdf", "doc", "docx", "pptx", "xlsx"}
    )


def analyze_zip(f: BinaryIO, strict: bool = False) -> List[Dict]:
    data = f.read()
    findings: List[Dict] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                name = info.filename.lower()
                _, ext = os.path.splitext(name)
                if ext in SUSP_EXT:
                    findings.append(
                        {
                            "rule": "zip_susp_executable",
                            "severity": "high",
                            "detail": f"Archive contains suspicious file: {name}",
                        }
                    )
                if _double_ext(name):
                    findings.append(
                        {
                            "rule": "zip_double_extension",
                            "severity": "high",
                            "detail": f"Double extension pattern: {name}",
                        }
                    )
                if name.endswith(".zip") and strict:
                    findings.append(
                        {
                            "rule": "zip_nested_archive",
                            "severity": "medium",
                            "detail": f"Nested archive found (strict): {name}",
                        }
                    )
    except zipfile.BadZipFile:
        pass
    return findings
