"""Minimal cross-platform GUI wrapper around the CLI scanner."""
from __future__ import annotations

import threading
import webbrowser
from pathlib import Path
from typing import List, Optional

try:  # pragma: no cover - GUI dependency resolved at runtime
    import PySimpleGUI as sg
except Exception:  # pragma: no cover - imported at runtime only
    print("PySimpleGUI is required for GUI. Run: pip install PySimpleGUI")
    raise

from .main import main as cli_main


def _parse_paths(raw: str) -> List[str]:
    return [segment.strip() for segment in raw.split(";") if segment.strip()]


def run_scan(paths: List[str], out_html: Optional[Path]) -> int:
    """Invoke the CLI scanner in-process to avoid subprocess complexity."""
    argv = ["scan", *paths]
    if out_html:
        argv += ["--report-html", str(out_html)]
    return cli_main(argv)


def app() -> None:
    """Launch the PySimpleGUI window."""
    sg.theme("SystemDefault")
    layout = [
        [sg.Text("Teacher-Safe Local File Scanner", font=("Segoe UI", 16))],
        [sg.Text("Pick files or a folder to scan (offline, safe defaults).")],
        [
            sg.Input(key="-PATH-", enable_events=True, expand_x=True),
            sg.FolderBrowse("Pick folder"),
            sg.FilesBrowse("Pick files"),
        ],
        [
            sg.Text("Output HTML report"),
            sg.Input(key="-OUT-", expand_x=True),
            sg.FileSaveAs("Save As", file_types=(("HTML", "*.html"),)),
        ],
        [
            sg.Button("Scan", key="-SCAN-", bind_return_key=True),
            sg.Button("Open Report", key="-OPEN-"),
            sg.Button("Quit"),
        ],
        [sg.Output(size=(100, 20), key="-LOG-")],
    ]
    window = sg.Window("Teacher-Safe Scanner", layout, finalize=True)
    report_path: Optional[Path] = None

    def do_scan() -> None:
        nonlocal report_path
        raw = window["-PATH-"].get()
        selected_paths = _parse_paths(raw)
        if not selected_paths:
            print("Please select at least one file or folder.")
            return
        missing = [path for path in selected_paths if not Path(path).exists()]
        if missing:
            print(f"The following paths do not exist: {', '.join(missing)}")
            return
        out_raw = window["-OUT-"].get()
        out_html = Path(out_raw) if out_raw else Path.cwd() / "scan_report.html"
        print("Starting scan...")
        try:
            exit_code = run_scan(selected_paths, out_html)
        except Exception as exc:  # pragma: no cover - defensive UI logging
            print(f"Scan failed: {exc}")
            return
        if out_html.exists():
            report_path = out_html
            print(f"Report saved to: {report_path}")
        else:
            report_path = None
            print("Scan completed but no report was generated.")
        print(f"Scan finished with exit code {exit_code}.")

    while True:
        event, _values = window.read()
        if event in (sg.WINDOW_CLOSED, "Quit"):
            break
        if event == "-SCAN-":
            thread = threading.Thread(target=do_scan, daemon=True)
            thread.start()
        if event == "-OPEN-":
            if report_path and report_path.exists():
                webbrowser.open(report_path.as_uri())
            else:
                print("No report to open yet.")
    window.close()


if __name__ == "__main__":  # pragma: no cover - GUI entry point
    app()
