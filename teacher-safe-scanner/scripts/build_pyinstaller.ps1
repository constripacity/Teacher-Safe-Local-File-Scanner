param([string]$Entry="scanner/gui.py", [string]$Name="TeacherSafeScanner")

pyinstaller --noconfirm --clean `
  --name $Name `
  --onefile `
  --windowed `
  --add-data "scanner/reporting/html_theme.css;scanner/reporting" `
  $Entry
