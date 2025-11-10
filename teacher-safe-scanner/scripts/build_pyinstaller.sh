#!/usr/bin/env bash
set -euo pipefail
ENTRY="${1:-scanner/gui.py}"
NAME="${2:-TeacherSafeScanner}"
pyinstaller --noconfirm --clean \
  --name "$NAME" \
  --onefile \
  --windowed \
  --add-data "scanner/reporting/html_theme.css:scanner/reporting" \
  "$ENTRY"
