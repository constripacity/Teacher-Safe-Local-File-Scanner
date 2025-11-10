# Teacher-Safe Local File Scanner

> **Defensive notice:** This project is provided for educational and defensive use by teachers and school IT staff. It is **not** a replacement for enterprise antivirus or endpoint protection.

![Demo GIF placeholder](https://img.shields.io/badge/Demo%20GIF-coming%20soon-blue)

> To add your own walkthrough, drop a GIF at `docs/demo.gif` and update this link.

Teacher-Safe Local File Scanner is a Python-based, offline-friendly toolkit that helps educators quickly triage student-submitted files before opening them. It performs static checks only—no execution of untrusted code—and produces human-readable and machine-readable reports.

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

## Safety, ethics, and limitations

- Static analysis only; no attempt is made to remove malware.
- Large or encrypted archives may hide malicious content the scanner cannot inspect.
- The heuristics prioritise minimizing false negatives but may produce false positives—always confirm with professional tools.
- The tool never executes or modifies untrusted binaries beyond safe hashing and metadata reads.

Read more in [SAFETY.md](SAFETY.md).

## Cross-platform notes

- Paths are managed with `pathlib`. When running on Windows, prefer PowerShell or CMD with UTF-8 enabled (`chcp 65001`).
- Quarantine sets read-only attributes; if you need to restore a quarantined file, manually adjust permissions via `attrib -r` on Windows or `chmod +w` on Unix.

## Development

```bash
pip install -r requirements.txt
pytest
ruff check .
```

## Contributing

We welcome defensive-minded contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for coding standards and submission guidelines.

## License

MIT License © Teacher Safe Maintainers
