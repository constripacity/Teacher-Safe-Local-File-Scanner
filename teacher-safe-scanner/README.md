# Teacher-Safe Local File Scanner

> **Defensive notice:** This project is provided for educational and defensive use by teachers and school IT staff. It is **not** a replacement for enterprise antivirus or endpoint protection.

![Demo GIF placeholder](https://img.shields.io/badge/Demo%20GIF-coming%20soon-blue)

> To add your own walkthrough, drop a GIF at `docs/demo.gif` and update this link.

Teacher-Safe Local File Scanner is a Python-based, offline-friendly toolkit that helps educators quickly triage student-submitted files before opening them. It performs static checks only—no execution of untrusted code—and produces human-readable and machine-readable reports.

## Table of contents

1. [Features](#features)
2. [Quickstart](#quickstart)
3. [How scanning works](#how-scanning-works)
4. [Command reference](#command-reference)
5. [Optional defensive plugins](#optional-defensive-plugins)
6. [Workflow guidance for flagged files](#workflow-guidance-for-flagged-files)
7. [Safety, ethics, and limitations](#safety-ethics-and-limitations)
8. [Cross-platform notes](#cross-platform-notes)
9. [Reports and outputs](#reports-and-outputs)
10. [Troubleshooting & FAQ](#troubleshooting--faq)
11. [Development](#development)
12. [Contributing](#contributing)
13. [License](#license)

If you are new to command-line tools, start with the [Beginner Guide](BEGINNERS_GUIDE.md) for a slower, step-by-step walkthrough.

## Features

- Static detectors for risky constructs in ZIP, Office, PDF, and image files
- Heuristic scoring with clear severity labels
- Console, JSON, and HTML reporting
- Optional directory watch mode using polling
- Quarantine helper that moves, never deletes, suspicious files
- Cross-platform (Windows, macOS, Linux) with standard library defaults
- Optional integrations with `python-magic` and `yara-python`

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\\Scripts\\activate
pip install -r requirements.txt
python examples/generate_benign_samples.py  # Materialise demo files
```

### Scan files or folders

```bash
python -m scanner.main scan ./examples/benign_samples --max-file-size 5000000 --threads 4
```

- Exit code `0`: no suspicious findings
- Exit code `1`: caution or suspicious findings
- Exit code `2`: high severity findings
- Exit code `3`: internal scanner error

### Watch a directory (polling, non-blocking)

```bash
python -m scanner.main scan --watch ./incoming
```

### Produce reports

```bash
python -m scanner.main scan submissions --output scan_report.json
python -m scanner.main report scan_report.json --html --output scan_report.html
```

### Quarantine a file

```bash
python -m scanner.main quarantine ./submissions/suspicious.docx --dest ./quarantine
```

The quarantine command moves the file safely, sets read-only permissions, and leaves a `.meta.json` file with provenance details.

### Refreshing the benign examples

If you delete the generated examples or clone the repository fresh, run:

```bash
python examples/generate_benign_samples.py
```

The script recreates a harmless text file, a minimal PNG image, and a macro-free `.docx` document without storing binary fixtures in the repository.

## How scanning works

The scanner combines lightweight type identification, static detectors, and heuristic scoring:

| Phase | What happens | Key modules |
| --- | --- | --- |
| Discovery | Files are walked recursively (respecting `--max-file-size`) and hashed using streaming reads. | [`scanner.utils`](scanner/utils.py) |
| Type sniffing | If `python-magic` is enabled, MIME detection is delegated; otherwise magic bytes are inspected. | [`scanner.scanner_core`](scanner/scanner_core.py) |
| Detection | Format-specific rules look for risky markers (e.g., macros, embedded executables, appended payloads). | [`scanner.detectors`](scanner/detectors.py) |
| Scoring | Each finding contributes a weighted score mapped to Safe/Caution/Suspicious/High labels. | [`scanner.heuristics`](scanner/heuristics.py) |
| Reporting | Results are aggregated into JSON, console, or HTML outputs. | [`scanner.reporters`](scanner/reporters.py) |

The entire pipeline avoids running untrusted content and is safe to execute on offline, air-gapped devices.

## Command reference

The CLI exposes three subcommands and several shared options:

### `scan`

Scan one file or a directory tree.

```bash
python -m scanner.main scan <path> [--output report.json] [--threads 8] [--max-file-size 200000000]
```

Useful flags:

- `--watch <folder>`: poll for new files while continuing to monitor previously scanned ones.
- `--use-magic` / `--use-yara`: opt into external libraries when installed.
- `--max-file-size`: skip overly large submissions to save time.
- `--threads`: increase if you have many CPU cores and fast storage.

The scan command exits with a severity-driven code so it integrates well with CI or folder monitors.

### `quarantine`

Move suspicious files to a safe holding area without deleting them.

```bash
python -m scanner.main quarantine ./submissions/suspicious.docx --dest ./quarantine
```

The destination receives a read-only copy plus a `.meta.json` file recording the original location, hash, and timestamp.

### `report`

Render previously generated JSON results into other formats.

```bash
python -m scanner.main report scan_report.json --html --output scan_report.html
```

Omit `--html` to stream a human-readable console summary instead.

## Optional defensive plugins

Install optional packages only if your environment permits:

```bash
pip install -r requirements-optional.txt
```

- `python-magic`: richer MIME identification (`--use-magic`)
- `yara-python`: experimental pattern matching (`--use-yara`)

The CLI flags are opt-in, and the scanner gracefully degrades when the libraries are unavailable.

## Workflow guidance for flagged files

1. **Do not open the file.** Treat warnings as serious until reviewed by IT.
2. Move the file to the quarantine folder for record keeping.
3. Escalate to your IT or security team with the JSON/HTML report.
4. Review in an isolated virtual machine if your institution allows it.
5. When in doubt, collect additional context (e.g., student name, assignment) in a secure ticketing system.

## Safety, ethics, and limitations

- Static analysis only; no attempt is made to remove malware.
- Large or encrypted archives may hide malicious content the scanner cannot inspect.
- The heuristics prioritise minimizing false negatives but may produce false positives—always confirm with professional tools.
- The tool never executes or modifies untrusted binaries beyond safe hashing and metadata reads.

Read more in [SAFETY.md](SAFETY.md).

## Cross-platform notes

- Paths are managed with `pathlib`. When running on Windows, prefer PowerShell or CMD with UTF-8 enabled (`chcp 65001`).
- Quarantine sets read-only attributes; if you need to restore a quarantined file, manually adjust permissions via `attrib -r` on Windows or `chmod +w` on Unix.
- Polling-based watch mode relies on filesystem timestamps; on slow or networked drives expect a 10-second delay before changes are detected.
- For macOS Gatekeeper prompts, run `xattr -dr com.apple.quarantine <path>` only on files you trust and after verifying reports.

## Reports and outputs

Reports follow a stable JSON schema so they can be ingested by help-desk systems:

```json
{
  "path": "submissions/homework1.zip",
  "sha256": "abc123...",
  "size": 34567,
  "magic_type": "zip",
  "issues": [
    {"code": "exe_in_zip", "description": "Found executable file payload.exe inside archive", "evidence": "payload.exe"},
    {"code": "double_extension", "description": "Filename uses double extension 'report.pdf.exe'", "evidence": "report.pdf.exe"}
  ],
  "score": 75,
  "severity": "Suspicious"
}
```

When exporting HTML the report includes:

- A safety banner reminding readers not to open flagged files.
- A severity-coloured table summarising each item.
- Collapsible detail sections for detector evidence.
- Footer tips on next steps for educators.

Console output defaults to a clean table suitable for terminal screenshots. Use `--verbose` during scans for additional logging.

## Troubleshooting & FAQ

**The scanner skips files larger than expected.**

- Confirm the `--max-file-size` flag; the default is 100 MB. Some learning management systems export multi-gigabyte ZIPs that may need a higher limit.

**`python-magic` or `yara-python` import errors appear.**

- Ensure you installed `requirements-optional.txt`. On Windows you may need the Visual C++ Build Tools; on macOS install Homebrew `libmagic` first.

**Watching a network share misses changes.**

- Keep the watch directory local when possible. The default 10-second polling interval may drift on congested networks—re-run the command if scans appear delayed.

**How do I update the benign sample files?**

- Run `python examples/generate_benign_samples.py --force` to regenerate all fixtures. The script never overwrites files unless the hash changes, so it is safe to run repeatedly.

**Can I integrate results into another system?**

- Yes. The JSON report is linearly structured. Use `jq`, Python, or your preferred language to parse the `issues` array per file. The exit code makes automation straightforward.

## Development

```bash
pip install -r requirements.txt
pytest
ruff check .
```

Recommended editor settings:

- Enable `black`-style formatting at 88 columns.
- Turn on type checking (MyPy or Pyright) for early detection of annotation issues.
- Configure your IDE to respect `.editorconfig` if present.

## Contributing

We welcome defensive-minded contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for coding standards and submission guidelines.

## License

MIT License © Teacher Safe Maintainers
