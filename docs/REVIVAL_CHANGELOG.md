# Revival changelog — 0.2.0 → 0.3.0

**Date:** 2026-09-02
**Base:** commit `ad1b6f3` (`v0.2.0`)
**Scope:** 41 tracked files modified or deleted; 58 new files, two of which are
this document and `docs/REVIVAL_AUDIT.md`.
`git diff --shortstat` reports `41 files changed, 3817 insertions(+), 1929 deletions(-)`
against the tracked set; the new modules, tests and corpus are untracked
additions on top of that.

This document records what changed and, in the Verification section, exactly
what was executed to check it. The companion document `docs/REVIVAL_AUDIT.md`
records the state that made these changes necessary, with reproductions.

---

## Security and correctness

### A file that was not checked is no longer called safe

`scanner/scanner_core.py` returned `severity="Safe"` for any file it failed to
`stat()` and for any file past the size limit. There was no vocabulary for "I did
not look" — `scanner/heuristics.py::SEVERITY_BANDS` offered only Safe, Caution,
Suspicious and High.

`Verdict.COULD_NOT_INSPECT` (`scanner/findings.py`) now exists as a first-class
outcome, and `scanner/verdict.py` Rule 1 makes it unreachable-past: any finding
carrying `inspection_incomplete=True` prevents a `LIKELY_SAFE` result. The
sources of that flag are all the places the old code went quiet: oversized files,
unreadable files, symlinks, corrupt archives, encrypted archive entries, encrypted
PDFs, depth-limited nesting, a truncated read, a detector exception, and any
container format with no detector at all
(`scanner_core.UNINSPECTABLE_CONTAINERS` / `UNINSPECTABLE_SUFFIXES` — `.rar`,
`.7z`, `.tar`, `.gz`, `.rtf`, `.iso`, `.msg` and others).

This is the single most important change in the release. A teacher reading a
green row must be able to believe it.

### Every read is bounded

The four old rule modules each began `data = f.read()`. With the default 100 MB
size limit and four threads, that is up to 400 MB of attacker-chosen bytes
resident before any regex ran over them.

`scanner/limits.py` is a single frozen dataclass holding every ceiling the
scanner obeys — read size, head/tail windows, archive member count, nesting
depth, total uncompressed bytes, compression ratio, nested-extract bytes,
findings per file, text scan bytes, URLs reported. Nothing in `scanner/` calls
`read()` without a bound. Measured on four 64 MB files at the default thread
count: peak RSS fell from **281.5 MB to 26.7 MB**.

### Symlinks are not followed

`utils.iter_directory_files` yielded symlinked files and `sha256_stream` opened
them. A link to `/dev/zero` in a scanned folder hung the scan indefinitely
(reproduced: killed at a 20-second timeout, still hashing).
`scanner_core.iter_targets` now prunes symlinked directories and `scan_file`
reports a symlink as `symlink_not_followed` / `COULD_NOT_INSPECT` without opening
it. `--follow-symlinks` exists for the case where a teacher knows the folder is
trustworthy.

### Quarantine no longer destroys student work

`move_to_quarantine` used `dest_dir / src.name` with no collision handling. Two
students submitting `assignment.docx` produced one file: the second overwrote the
first, and the `.meta.json` record of the first along with it.

`scanner/quarantine.py::QuarantineStore` stores each file as
`<name>.<first-12-of-sha256>.quarantined`, so collisions cannot occur; appends to
a JSONL manifest recording the original path, hash, size, reason, verdict and
timestamps; creates the directory `0700` and stores files `0600`; and clears
execute bits. The `.quarantined` suffix means the operating system has no handler
for the file, so a double-click does nothing. `restore` verifies the stored hash
before moving a file back and refuses to overwrite an existing file or to restore
the same entry twice.

### Archives are analysed for the things that actually matter

`scanner/detectors/archive.py` replaces `zip_rules.py`. It reads the central
directory rather than extracting, and adds: path traversal (`../`, absolute
paths, Windows drive letters, UNC paths, backslash separators —
`base.looks_like_path_escape`), per-entry compression ratio and total
uncompressed size against the bomb thresholds, encrypted entries, NUL bytes and
bidi/zero-width characters in member names, a member-count cap, and bounded
recursion into nested archives through an in-memory stream that never writes to
disk. OOXML containers are recognised and routed to the Office detector rather
than being reported as "an archive containing archives", which would have flagged
every normal `.docx`.

### XML from untrusted documents is never handed to `xml.etree`

`scanner/detectors/office.py` parses OOXML relationship files with `defusedxml`
when it is installed and falls back to a byte-level regex scan when it is not.
The stdlib parser is never used on submission content. `defusedxml` is an
optional extra (`pip install -e ".[xml]"`), and the fallback path was verified to
produce identical verdicts on the whole corpus (see Verification).

### Student-controlled bytes cannot forge report output

`reporters.render_console_table` wrote paths straight to the terminal. A filename
containing `\x1b[2K\r` erases its own row and can print a reassuring line in its
place. `reporters.sanitize_display` now replaces bidi controls, zero-width
characters and every non-printable character with `<U+XXXX>` before anything is
written to a terminal, an HTML report, or the GUI. HTML escaping is applied on
top of that.

### The exit code now means something

v0.2.0 mapped `Suspicious` and `Caution` to the same exit code, and returned **0**
— "clean" — when the target path did not exist:

```
$ python -m scanner scan /tmp/does-not-exist-typo
WARNING scanner.main: Target ... does not exist
exit code = 0
```

Exit codes are now `0` clean, `1` needs attention (caution or not-checked), `2`
do not open, `3` scanner error, `4` usage error, documented in `--help`, and a
missing target is a usage error.

### Other correctness fixes

- **Every valid PNG was flagged.** `detect_image_appended_data` treated the
  4-byte CRC after the `IEND` chunk type as appended data. `detectors/image.py`
  now parses the chunk structure.
- **Every real Word document was flagged.** `office_rules.analyze_office` raised
  a medium finding on the presence of `settings.xml`, which every `.docx` has.
  Removed entirely.
- **PDF tokens spanning a read boundary were missed.** The old loop carried 10
  bytes across a 4096-byte boundary while searching for 13-byte tokens.
  `base.iter_windows` takes the overlap as a parameter and validates it against
  the window size; `detectors/pdf.py` derives it from the longest marker.
- **`/JS` and `/JavaScript` were two findings for one fact.** Markers are grouped
  in `pdf._MARKER_GROUPS` and each group fires once.
- **Large appended image payloads were reported as clean.** The old check read
  only the last 8 KB, so the end marker fell outside the window precisely when
  the payload was big. `detectors/image.py` searches backwards in growing
  windows and reports "terminator not found within the tail limit" as a finding
  rather than as silence.
- **Detector exceptions no longer abort a scan.** `scan_file` catches them,
  records the error, and returns `COULD_NOT_INSPECT`.
- **Repetition can no longer inflate the risk score.** `verdict.risk_score` caps
  each finding code's contribution at twice a single hit.

---

## Added

- **`scanner/findings.py`** — `Finding`, `Severity`, `Confidence`, `Verdict`.
  Severity ("how bad if true") and confidence ("how sure we are") are separate
  axes. Every finding carries `plain`, `why`, `action` and `evidence`, so a
  report can justify each line to a non-technical reader instead of printing
  `pdf_token — PDF contains token /AA`.
- **`scanner/verdict.py`** — four stated rules replacing the additive weight
  table, with the rule that fired printed in the report. Documented in
  `docs/SCORING.md` so a school IT reviewer can disagree with a specific rule
  rather than with an unexplained integer.
- **`scanner/limits.py`** — every resource ceiling in one reviewable struct.
- **`scanner/triage.py`** — folder-level answer: counts per verdict, worst-first
  ordering, duplicate detection by SHA-256, a batch-wide finding roll-up, and a
  one-sentence headline written to be pasted into an email
  (`"15 of 31 files should not be opened. 4 more need a closer look."`).
- **`scanner/detectors/base.py`** — bounded read primitives, magic sniffing,
  suffix-chain analysis that ignores version fragments (`report.v2.final.docx`),
  bidi and invisible character detection, path-escape detection.
- **`scanner/detectors/general.py`** — checks that apply to any file: filename
  deception, extension-versus-content mismatch by magic bytes, executable content
  under any name, punycode / raw-IP / shortener links in text.
- **`scanner/gui_model.py`** — everything the desktop window displays, with no Tk
  import, so it is unit-testable on a machine with no display (which is exactly
  the machine this revival was performed on).
- **68 finding codes** across the six detector modules, each with teacher-facing
  text. `tests/test_detectors_documents.py::test_every_finding_has_teacher_facing_text`
  asserts none is left blank.
- **New detections** not present at all in v0.2.0: archive path traversal;
  decompression-bomb ratio and total; encrypted archive entries; NUL, zero-width
  and right-to-left-override characters in filenames and archive members; Office
  remote-template injection (`attachedTemplate` external relationship);
  DDE/DDEAUTO fields; ActiveX controls; legacy OLE macro storage; PDF `/Launch`;
  PDF header not at offset 0; PDF data after `%%EOF`; image polyglots; impossible
  PNG chunk lengths; oversized image metadata.
- **Benign test corpus** — `examples/generate_benign_samples.py` writes 30
  harmless files that reproduce the *structure* of risky ones (payloads are
  `echo "this is a harmless sample..."`), plus a README table naming what each is
  meant to trigger.
- **`scripts/check_corpus.py`** — the detection regression gate. It asserts both
  directions: every hostile-shaped sample reaches its expected verdict *and*
  carries its expected finding code, and every clean sample stays clean. A
  weakened detector and a noisy detector both fail it.
- **`quarantine-list` and `restore` CLI commands**, and `gui` and `make-samples`
  subcommands.
- **`teacher-safe-scan.spec` and `scripts/build_binary.py`** — a PyInstaller
  build that emits a SHA-256 checksum next to the binary and prints an explicit
  notice that the artefact is unsigned.
- **`docs/SCORING.md`** and **`docs/ARCHITECTURE.md`**.

---

## Changed

- **The GUI is Tkinter, not PySimpleGUI.** `requirements.txt` pinned
  `PySimpleGUI==4.60.5.1`, itself a patch for an earlier yank (repo commit
  `f26df55`: "4.60.5 was yanked from PyPI"). Both CI workflows installed *all*
  their tooling through `pip install -r requirements.txt`, so an unavailable
  PySimpleGUI did not merely break the window — it broke the install, and with it
  lint, types and tests. Tkinter ships with CPython. The window is now
  `scanner/gui.py` (widgets only) over `scanner/gui_model.py` (logic, tested).
- **The runtime requires nothing outside the standard library.** All former
  requirements are optional extras (`xml`, `magic`, `yara`, `build`, `dev`).
  `requirements.txt` is now a comment block explaining that, and
  `requirements-dev.txt` holds the tooling.
- **Detector dispatch is by sniffed content first, extension second**, so a
  Windows PE named `holiday_photo.png` is analysed as a program. v0.2.0 dispatched
  on extension and caught this only via a 50-point `MZ` check that landed in
  `Suspicious`, not `High`.
- **One open per file.** `scan_file` opens the handle once and passes it to the
  detectors, instead of each detector re-opening and re-reading the path.
- **HTML report rewritten** (`scanner/reporters.py`): self-contained, no
  JavaScript, no external assets, no network requests, grouped worst-first, with
  the plain-English explanation and recommended action for every finding. The
  v0.2.0 report required JavaScript and its primary call to action was a button
  that copied a shell command to the clipboard.
- **Watch mode** keeps an mtime/size index and re-scans only what changed, rather
  than `rglob('*')` over the whole tree every ten seconds.
- **Configuration consolidated into `pyproject.toml`.** At HEAD a root
  `ruff.toml` shadowed `[tool.ruff.lint]` in `pyproject.toml` — Ruff prefers
  `ruff.toml` and does not merge — so the declared `select = ["E","F","B","I"]`
  never applied; under the intended rule set the tree had 9 findings. Similarly
  `mypy.ini` shadowed `[mypy]` in `setup.cfg`, so type checking ran at Python 3.11
  and never at 3.10, the declared minimum. Both shadowing files are gone.
- **CI and release workflows rewritten.** CI now runs a
  Linux/macOS/Windows × Python 3.10/3.12 matrix, a separate detection-corpus job,
  a binary build, and a job that runs the scanner in a bare virtualenv with zero
  dependencies to catch exactly the class of failure that broke v0.2.0. The
  release workflow checksums each artefact, smoke-tests the built binary, and
  states in the release body that the binaries are unsigned and what macOS and
  Windows will do about that.
- **`README.md`, `BEGINNERS_GUIDE.md` and `SAFETY.md`** rewritten to describe what
  the code does. `SAFETY.md` gained sections on the absolute
  never-execute constraint, on resource limits as part of the threat model, and
  on the honest limits the product states in its own output.

---

## Removed

| Removed | Why |
| --- | --- |
| `scanner/heuristics.py` | The additive weight table. Superseded by `scanner/verdict.py`. |
| `scanner/detectors/zip_rules.py` | Unbounded `f.read()`, no traversal/bomb/encryption checks. Superseded by `detectors/archive.py`. |
| `scanner/detectors/pdf_rules.py` | Unbounded read, duplicate findings for one fact. Superseded by `detectors/pdf.py`. |
| `scanner/detectors/office_rules.py` | Unbounded read, and the `settings.xml` rule that flagged every Word document. Superseded by `detectors/office.py`. |
| `scanner/detectors/image_rules.py` | Whole-file read; the JPEG check was a single `endswith` test. Superseded by `detectors/image.py`. |
| `scanner/utils.py` | Split into `detectors/base.py` (reads, sniffing) and the hashing helper in `scanner_core.py`. Its `iter_directory_files` was the symlink hazard. |
| `scanner/reporting/html_theme.css` | The HTML report is now self-contained; the external stylesheet was a packaging liability in a frozen binary. |
| `ruff.toml`, `mypy.ini`, `setup.cfg` | Shadowing configuration. Everything is in `pyproject.toml`. |
| `requirements-optional.txt` | Replaced by `[project.optional-dependencies]`. |
| `scripts/build_pyinstaller.sh`, `.ps1` | Built from `scanner/gui.py` with `--windowed`, producing a binary with no working command line. Replaced by `teacher-safe-scan.spec` and `scripts/build_binary.py`. |
| `docs/README.md` | A placeholder asking someone to add a demo GIF. |
| The seven v0.2.0 test modules | Replaced by six modules that test verdicts, reporting, quarantine, the CLI and the GUI model, none of which had any coverage before. |

---

## Verification

Every command below was executed in this environment immediately before writing
this document. Environment: Ubuntu 24.04 (kernel 6.18), CPython 3.11.15,
`pytest 9.0.3`, `ruff 0.15.11`, `mypy 1.20.2`. Output is quoted verbatim.

### Test suite

```
$ pytest -q
........................................................................ [ 61%]
..................s...........................                           [100%]
=========================== short test summary info ============================
SKIPPED [1] tests/test_scanner_core.py:58: running as root: permissions are not enforced
117 passed, 1 skipped in 0.63s
```

118 tests collected across 6 modules: `test_detectors_archive.py` (19),
`test_detectors_documents.py` (26), `test_quarantine.py` (15),
`test_reporting_and_cli.py` (26), `test_scanner_core.py` (17),
`test_verdict.py` (15). The one skip is honest and self-declared: this
environment runs as root, where POSIX permission bits are not enforced, so the
test that asserts an unreadable file is not reported as safe cannot construct its
precondition. It is reported as skipped, not as passed.

Baseline for comparison, measured in a clean `git worktree` at `ad1b6f3`:

```
$ pytest -q
...........                                                              [100%]
11 passed in 0.06s
```

### Lint

```
$ ruff check scanner tests
All checks passed!
    (exit 0)

$ ruff check scanner tests examples      # the command CI runs
All checks passed!
    (exit 0)
```

Under `pyproject.toml`'s `select = ["E", "F", "B", "I"]`, which at HEAD was
shadowed by `ruff.toml` and therefore never applied. Running the same rule set
against the HEAD worktree gives the baseline:

```
$ ruff check --config pyproject.toml scanner tests
5   E501  line-too-long
4   I001  unsorted-imports
Found 9 errors.
```

### Types

```
$ mypy scanner
pyproject.toml: note: unused section(s): module = ['magic']
Success: no issues found in 19 source files
    (exit 0)
```

The note was accurate, and acting on it was the right response: `python-magic`
was declared in `[[tool.mypy.overrides]]` and as a `magic` extra, but nothing in
`scanner/` imported it — `scanner.detectors.base.sniff_magic` reads the header
bytes itself. The extra and the override entry were both removed before
shipping, and `mypy` no longer emits the note.

Baseline at HEAD: `Success: no issues found in 14 source files`.

Running `mypy` over `tests/` additionally reports 7 `import-not-found` errors for
`pytest`. That is an artefact of this environment — `mypy` is installed as an
isolated `uv` tool with its own interpreter that cannot see `pytest` — not a
defect in the tree. CI installs both into the same environment and runs
`mypy scanner`.

### Detection regression gate

```
$ python scripts/check_corpus.py
corpus OK: 31 samples — 15 correctly blocked, 9 correctly clean, no false positives.
    (exit 0)
```

This asserts a per-file expected verdict *and* an expected finding code for every
sample. Running the same corpus through the v0.2.0 code gives 11 risky samples
labelled `Safe` — `archive_path_traversal.zip`, `archive_zip_bomb_shape.zip`,
`archive_password_protected.zip`, `broken_upload.zip`, `coursework.7z`,
`essay.rtf`, `pdf_appended_payload.pdf`, `office_remote_template.docx`,
`office_dde_field.docx`, `office_embedded_object.docx` and
`image_large_appended.jpg` — plus spurious findings on 3 of the 9 clean samples
(`clean_diagram.png`, `clean_report.docx`, `clean_essay.txt`). The side-by-side
table is in `docs/REVIVAL_AUDIT.md`.

### End-to-end CLI, and the zero-dependency claim

Reproducing the CI job that runs the scanner in a virtualenv with nothing
installed:

```
$ python -m venv /tmp/bare
$ /tmp/bare/bin/python -c "import importlib.util as u; print(u.find_spec('defusedxml') is not None)"
False
$ /tmp/bare/bin/python examples/generate_benign_samples.py --out /tmp/samples
Wrote 30 benign sample files to /tmp/samples
$ /tmp/bare/bin/python -m scanner --color never scan /tmp/samples --report-json /tmp/r.json
    (exit 2)
counts:   {'do_not_open': 15, 'review_with_caution': 4, 'could_not_inspect': 3, 'likely_safe': 9}
headline: 15 of 31 files should not be opened. 4 more need a closer look.
```

The same scan with `defusedxml 0.7.1` present produces the same counts and the
same exit code, so the byte-scan fallback in `detectors/office.py` was exercised
and agreed with the parsed path across the whole corpus.

### Report round-trip

```
$ python -m scanner --color never scan /tmp/corpus --report-json r.json --report-html r.html
    (exit 2)
$ python -m scanner --color never report r.json --html r2.html
    (exit 2)
$ python -c "print(open('r.html').read() == open('r2.html').read())"
True
```

The JSON report contains enough to regenerate a byte-identical HTML report and
the same exit code, which is what makes `report` usable for forwarding a scan to
IT.

The generated HTML was checked for external references:

```
$ grep -c 'href=\|src=' r.html
0
$ grep -o '<a [^>]*>\|<script[^>]*>\|<iframe' r.html
    (no matches)
```

No links, no scripts, no iframes, no network requests. URLs found in scanned
files appear only as HTML-escaped text inside `<code>` evidence blocks.

### Quarantine

The v0.2.0 data-loss case, run against the new store:

```
$ python -m scanner quarantine /tmp/qtest/a/assignment.docx --dest /tmp/qtest/q
Quarantined ... as assignment.docx.e7dcee3cc63d.quarantined
$ python -m scanner quarantine /tmp/qtest/b/assignment.docx --dest /tmp/qtest/q
Quarantined ... as assignment.docx.52579f5dd420.quarantined
$ ls -la /tmp/qtest/q
drwx------  .
-rw-------  assignment.docx.52579f5dd420.quarantined
-rw-------  assignment.docx.e7dcee3cc63d.quarantined
-rw-r--r--  quarantine-manifest.jsonl
$ python -m scanner restore 342393966d59 --dest /tmp/qtest/q
Restored to /tmp/qtest/a/assignment.docx     # content: ALICE
$ python -m scanner restore 342393966d59 --dest /tmp/qtest/q
error: Entry 342393966d59 was already restored to /tmp/qtest/a/assignment.docx
    (exit 3)
```

Both files survive, the directory is `0700` and the files `0600`, restore returns
the correct content to the correct path, and a second restore is refused.

### Regression reproductions

Each of these was run against both trees. HEAD result first, current result
second.

| Case | v0.2.0 | 0.3.0 |
| --- | --- | --- |
| Folder containing a symlink to `/dev/zero` | scan never finished (killed at 20 s) | `COULD_NOT_INSPECT` / `symlink_not_followed` in 0.00 s |
| A minimal valid PNG | `image_trailing_data` (false positive) | `LIKELY_SAFE`, no findings |
| A 20-link bibliography `.txt` | score 100, `High` | `LIKELY_SAFE`, no findings |
| `/EmbeddedFile` straddling offset 4096 | missed when 11 or 12 of its 13 bytes precede the boundary | found (regression test: `test_token_spanning_a_window_boundary_is_still_found`) |
| Four 64 MB files, 4 threads | peak RSS 281.5 MB | peak RSS 26.7 MB |
| `scan` on a non-existent path | exit 0 | exit 4, `error: ... does not exist` |
| Filename containing `\x1b[2K\r` | emitted raw into the terminal | rendered `essay<U+001B>[2K<U+000D>SCAN COMPLETE...` |
| Two files named `assignment.docx` quarantined | first destroyed | two entries, both intact |

### GUI fallback

`tkinter` is not installed in this environment, which makes the fallback path
directly testable:

```
$ python -m scanner gui
error: the desktop window needs Python's built-in tkinter, which is not available here (No module named 'tkinter').
  Debian/Ubuntu:  sudo apt install python3-tk
  Fedora:         sudo dnf install python3-tkinter
  macOS/Windows:  reinstall Python from python.org (tkinter is included)
The command line works without it:  teacher-safe-scan scan <folder>
    (exit 3)
```

---

## Not verified

Listed with the exact reason. None of these was assumed to work.

- **The PyInstaller binary.** Not built, on any platform. `pyinstaller` is not
  installed and cannot be installed: `pypi.org` and `files.pythonhosted.org` both
  return HTTP 403 through this environment's egress proxy. `teacher-safe-scan.spec`
  and `scripts/build_binary.py` were written and reviewed, and the release
  workflow smoke-tests the artefact it builds, but no frozen binary has ever been
  produced or executed. Treat the binary distribution as untested until a release
  run is observed.
- **Windows.** No Windows machine. Everything about extension hiding, SmartScreen,
  `.lnk` semantics, drive-letter and UNC path handling, and `%ProgramFiles%` in
  `scripts/windows_add_context_menu.reg` is reasoned from code, not observed. The
  path-escape logic for Windows-shaped paths is unit-tested on Linux
  (`test_path_traversal_is_detected` parametrises `"..\\..\\evil.txt"` and
  `"/etc/passwd"`), which tests the parser, not the platform.
- **macOS.** No macOS machine. Gatekeeper behaviour, notarisation, the
  `argv_emulation` flag in the spec, and the `ditto`/`xattr` instructions in the
  release notes are all unobserved.
- **The desktop window.** `import tkinter` fails here and there is no display, so
  `scanner/gui.py` has never been rendered. Its presentation logic lives in
  `scanner/gui_model.py`, which has no Tk import and is covered by four tests —
  but that is the model, not the window. Widget layout, drag-and-drop, threading
  behaviour and colour rendering are unverified.
- **The GitHub Actions workflows.** Never executed. The YAML was read and the
  individual commands were reproduced locally on Linux/CPython 3.11; the
  three-OS, two-Python matrix was not.
- **`python-magic` and `yara-python`.** Neither is installable here. The YARA
  code path was exercised only through its degraded branches
  (`yara_unavailable`, `yara_no_rules`) — no rule file has been compiled or
  matched. `python-magic` was not imported by `scanner/` at all, so the `magic`
  extra was removed rather than shipped as a dependency that does nothing.
- **Permission enforcement in quarantine.** The store sets `0700` / `0600` and
  the modes were observed on disk, but this environment runs as root, where those
  bits do not restrict access. The one test that depends on enforcement skips
  itself and reports the reason.
- **`pre-commit`.** `.pre-commit-config.yaml` is unchanged from v0.2.0 and still
  pins `ruff v0.6.9`, `black 24.8.0` and `mypy v1.11.2`. `pre-commit` is not
  installed and its hook repositories cannot be fetched without network, so the
  hooks were never run. `black` is not configured anywhere else in the project,
  so the hook and `pyproject.toml` may disagree about formatting.
- **Whether PySimpleGUI 4.60.5.1 is currently absent from PyPI.**
  `pip download PySimpleGUI==4.60.5.1` reports `from versions: none`, but all
  PyPI traffic returns 403 here, so "unavailable" cannot be distinguished from
  "blocked". The removal is justified independently — the repository's own commit
  `f26df55` records that the previous pin was yanked, and a mandatory GUI
  dependency in the install path for a standard-library-only scanner is wrong
  regardless.
- **Performance at realistic classroom scale.** The largest measured scan is 31
  files and four 64 MB files. No 500-submission folder, no network share, no
  spinning disk, no antivirus interference on the host.
- **A `.js` inside an archive still yields DO NOT OPEN.** This is a known,
  unresolved false positive for computing classes rather than an unverified
  claim: `archive_executable_member` is HIGH severity, and Rule 2 blocks on HIGH
  at medium *or* high confidence, so the `_is_code_assignment_shaped()`
  confidence downgrade changes the wording but not the verdict. Verified:
  `lab3.zip` containing `src/app.js` → `DO_NOT_OPEN`. The workaround is
  `--zip-rules off`.
