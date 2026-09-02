# Safety and scope

## This project is defensive only

Teacher-Safe Local File Scanner exists to help a teacher or school IT assistant
decide **which files not to open**. It detects; it never builds, packs, obfuscates
or executes anything.

Contributions that add offensive capability will be declined. That includes:
payload generation, exploitation, evasion testing against other products,
credential harvesting, or anything whose primary use is attacking rather than
triaging.

## The absolute constraint

**Untrusted content is never executed.** In this codebase that means, with no
exceptions:

- no macro is run, and no Office document is opened by an Office application
- no PDF is rendered, and no PDF library that executes embedded content is used
- no archive is ever extracted to a filesystem path
- no image is decoded by an image library
- no file is passed to a shell, an interpreter, or `subprocess`

Detectors read bytes and report structure. `tests/test_detectors_archive.py::test_nothing_is_written_to_disk`
guards the archive case explicitly.

## Resource limits are part of the threat model

Hostile input tries to exhaust the machine that inspects it. Every bound the
scanner obeys lives in one struct, `scanner/limits.py`:

| Limit | Default | Guards against |
| --- | --- | --- |
| `max_file_size` | 100 MB | reading an enormous submission into memory |
| `max_read_bytes` | 8 MB | a detector holding a whole file |
| `max_archive_members` | 5,000 | central-directory floods |
| `max_archive_depth` | 3 | archive-in-archive recursion |
| `max_total_uncompressed` | 512 MB | decompression bombs |
| `max_compression_ratio` | 200:1 | per-entry bomb ratio |
| `max_nested_extract_bytes` | 16 MB | bounded nested reads |
| `max_findings_per_file` | 200 | report and memory blowup |

Anything cut off by a limit is reported as **COULD NOT FULLY INSPECT** — never
as safe.

## No malware in this repository

The test corpus in `examples/generate_benign_samples.py` reproduces the
*structure* of risky files using inert payloads (`echo "harmless test payload"`).
An archive member that escapes its folder contains a text file. A "polyglot" PNG
has a real, harmless ZIP appended.

Never commit a real sample, even a defanged one, even in an encrypted archive.
If a detector needs a real-world sample to develop against, obtain it from a
malware repository under your own account, keep it out of git, and contribute the
detector plus a synthetic fixture.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). In short: for a flaw in this scanner, please open
a private security advisory rather than a public issue — a bypass in a triage
tool is a real risk to the people using it.

## Honest limits, stated in the product

The tool says all of the following in its own output, and this project treats
weakening any of them as a bug:

- it is **not antivirus** and has no signature database
- "likely safe" means "nothing matched the checks this tool performs"
- a novel technique the tool does not model will come back clean
- encrypted, oversized and corrupt files are reported as *unchecked*, and
  unchecked is not clean
