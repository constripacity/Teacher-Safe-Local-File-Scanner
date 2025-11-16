from typing import BinaryIO, Dict, List
import zipfile
import io


# Detects macro-enabled Office docs and macro streams
def analyze_office(f: BinaryIO, strict: bool = False) -> List[Dict]:
    data = f.read()
    findings: List[Dict] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
            if any(name.endswith("vbaProject.bin") for name in names):
                findings.append(
                    {
                        "rule": "office_vba_project",
                        "severity": "high",
                        "detail": "vbaProject.bin present (macros).",
                    }
                )
            if any("settings.xml" in name for name in names):
                findings.append(
                    {
                        "rule": "office_auto_actions_hint",
                        "severity": "medium",
                        "detail": "Settings file may define auto behaviors.",
                    }
                )
    except zipfile.BadZipFile:
        # Not OOXML .docx/.pptx/.xlsx; could be legacy binary. v0.1: skip deep OLE parse.
        pass
    return findings
