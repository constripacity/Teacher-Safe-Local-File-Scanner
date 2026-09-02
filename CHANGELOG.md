# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-09-02

A revival release. The detection engine, severity model, reporting and
quarantine were rewritten; the dependency that made the project uninstallable
was removed.

### Added
- **Folder-level triage.** The unit of work is now a folder of submissions, not
  a single file. Output is a worst-first table with a plain-English headline
  ("15 of 29 files should not be opened"), counts per verdict, duplicate
  detection by hash, and a batch-wide finding roll-up.
- **Four-verdict model** — `LIKELY SAFE TO REVIEW`, `REVIEW WITH CAUTION`,
  `DO NOT OPEN — CONTACT IT`, `COULD NOT FULLY INSPECT` — with the last of these
  explicitly never treated as safe.
- **Explainable findings.** Every finding now carries plain-English text, why it
  matters, a recommended action, concrete evidence, and separate severity and
  confidence. See `docs/SCORING.md`.
- **New detections**: archive path traversal; decompression-bomb ratio and total;
  encrypted archive entries; NUL, zero-width and right-to-left-override characters
  in filenames and archive members; Office remote-template injection
  (`attachedTemplate` external relationship); DDE/DDEAUTO fields; ActiveX
  controls; legacy OLE macro storage; PDF `/Launch`; PDF header not at offset 0;
  image polyglots (ZIP/PE/PDF after the terminator); impossible PNG chunk
  lengths; oversized image metadata; extension-vs-content mismatch by magic bytes;
  punycode, raw-IP and shortened links in text.
- **Quarantine restore.** `quarantine-list` and `restore` commands, an
  append-only JSONL manifest recording original path and SHA-256, and hash
  verification on the way back out.
- **`scanner/limits.py`** — every resource ceiling the scanner obeys, in one
  reviewable struct.
- **Benign test corpus** (`examples/generate_benign_samples.py`): 28 harmless
  files reproducing the structure of risky ones, plus
  `scripts/check_corpus.py`, a detection-regression gate asserting both that
  every hostile-shaped sample is caught and that every clean sample stays clean.
- **PyInstaller spec and `scripts/build_binary.py`**, producing a single
  executable with a SHA-256 checksum, plus a release workflow that smoke-tests
  the built binary before publishing.
- Cross-platform CI matrix (Linux/macOS/Windows × Python 3.10/3.12) including a
  job that runs the scanner in a bare virtualenv with **zero** dependencies.
- `docs/SCORING.md` and `docs/ARCHITECTURE.md`.

### Changed
- **The GUI is now Tkinter instead of PySimpleGUI.** PySimpleGUI moved to a paid
  licence and its old versions were pulled from PyPI, which is why
  `pip install -r requirements.txt` failed outright on the previous release.
  Tkinter ships with CPython and freezes cleanly. Display logic moved to
  `scanner/gui_model.py`, which has no Tk import and is unit tested.
- **The runtime now requires nothing outside the standard library.** All previous
  requirements are optional extras.
- HTML report rewritten: self-contained, no JavaScript, no network requests,
  light/dark aware, printable, grouped worst-first.
- Watch mode re-scans only files whose mtime or size changed, instead of
  `rglob('*')` over the whole tree every ten seconds.
- Detector dispatch is by sniffed content type first and extension second, so a
  program renamed `holiday_photo.png` is analysed as a program.

### Fixed
- **Oversized, unreadable and errored files were reported as `Safe`.** They are
  now `COULD NOT FULLY INSPECT`. This was the most dangerous defect in the
  previous release.
- **Every `.docx` was flagged.** `analyze_office` raised
  `office_auto_actions_hint` on the presence of `word/settings.xml`, which exists
  in every Word document ever saved. Removed.
- **PDF tokens spanning a chunk boundary were missed.** The scanner used a
  10-byte overlap while searching for tokens up to 13 bytes long. Overlap is now
  derived from the longest token, with a regression test.
- **`/JS` and `/JavaScript` were counted as two separate findings**, doubling the
  score for one fact. Markers are now grouped and fire once.
- **Appended image payloads larger than 8 KB were reported as clean.** The
  trailing-data check only read the last 8 KB, so the terminator fell outside the
  window precisely when the payload was large. It now searches backwards in
  growing windows, and reports "terminator not found within the tail limit" as a
  finding rather than silence.
- **Quarantining two files with the same name destroyed the first.** The
  destination was `dest_dir / src.name` with no collision handling. Stored names
  now include a content hash.
- **Quarantined files kept their original extension**, so a double-click still
  handed them to the shell. They now gain a `.quarantined` suffix and lose their
  execute bits.
- Symlinks are no longer followed: a link to `/dev/urandom` in an untrusted
  folder would have hung the hasher indefinitely.
- Detector exceptions no longer abort a scan; the file becomes
  `COULD NOT FULLY INSPECT` with the error recorded.
- Repeated identical findings can no longer inflate the risk score
  (per-finding-code cap).
- Report output sanitises bidi and zero-width characters, so a filename using a
  right-to-left override cannot spoof its own rendering *inside the report*.

### Security
- All archive and document reads are bounded; decompression bombs, member
  floods and unbounded recursion are detected and refused rather than absorbed.
- Archives are never extracted to disk, so a traversal path can never be written.
- OOXML relationship XML is parsed with `defusedxml` when available and by byte
  scan when not — never by stdlib ElementTree on untrusted input.
- Quarantine directory is created `0700`, stored files `0600`.

### Removed
- `PySimpleGUI` dependency (licensing; see above).
- `scanner/heuristics.py` additive weight table, superseded by
  `scanner/verdict.py`.
- `scanner/detectors/{zip,pdf,office,image}_rules.py`, superseded by the
  detectors in the same package.
- Duplicated `mypy.ini`, `ruff.toml` and `setup.cfg` configuration, now in
  `pyproject.toml`.

## [0.2.0] — 2026-05-29
- CI fixes and release repair.

## [0.1.0]
- Initial release: static detectors for ZIP/Office/PDF/image, heuristic scoring,
  console/JSON/HTML reporting, PySimpleGUI window, quarantine helper.
