# Revival audit — Teacher-Safe Local File Scanner v0.2.0

## What this is

This is the baseline audit of the project as it stood at commit `ad1b6f3`
(`v0.2.0`, the last released state) before the 0.3.0 revival. It records what the
code actually did, what worked, what did not, and — as precisely as possible —
what could not be established from the environment this audit was performed in.
It is written for someone deciding whether to point this tool at a folder of
student submissions.

**How it was produced.** The v0.2.0 tree was checked out clean with
`git worktree add /tmp/ts-head HEAD` and read in full: every module in
`scanner/`, every test, every workflow, and the packaging metadata. The test
suite, `ruff` and `mypy` were run against that checkout. The scanner itself was
then run — as a library and through its CLI — against a corpus of 30 harmless
files that reproduce the *structure* of risky submissions (archive traversal,
macro documents, appended payloads, filename deception). Every behavioural claim
below was reproduced by execution, and the reproducing snippet is included where
it is short enough to be useful. Nothing here is taken from the README, which
described behaviour the code did not have.

Environment: Linux (Ubuntu 24.04, kernel 6.18), CPython 3.11.15, no network
(`pypi.org` and `files.pythonhosted.org` both answer HTTP 403 through the egress
proxy), no macOS, no Windows, no `tkinter`, no display.

---

## What worked at HEAD

Being fair about this matters, because most of what follows is critical.

- **The core promise was kept.** Nothing in v0.2.0 executed a submission. No
  macro was run, no PDF was rendered, no archive was extracted to disk, no image
  was decoded. Every detector read bytes. This is the one thing that absolutely
  had to be right, and it was.
- **The project was genuinely offline.** No detector, reporter or CLI path made
  a network request.
- **Quarantine moved rather than deleted.** `move_to_quarantine()` used a
  rename-with-copy-fallback and verified the copied size before unlinking the
  source. The intent — never destroy a student's work — was right, even though
  the implementation had a hole (below).
- **Streaming hashing was correct.** `utils.sha256_stream()` read in 1 MB chunks
  rather than slurping the file, and `safe_read_head` / `safe_read_tail` were
  careful about `OSError`.
- **The structure was sane.** Detectors, orchestration, reporting, quarantine and
  CLI were already separate modules with docstrings. The revival kept that shape.
- **`ruff` and `mypy` passed**, and the 11 tests passed, on first run with no
  fixing. The project was not rotten in the "does not even import" sense.
- **`ScanConfig` already had per-family `off | normal | strict` switches**, which
  is the right idea: a computing teacher and an English teacher need different
  sensitivity.

---

## What was broken

### 1. A file that was not checked was reported as safe

This is the defect that matters most, because it inverts the tool's purpose.

`scanner/scanner_core.py::_scan_file`:

```python
    try:
        size = path.stat().st_size
    except OSError as exc:
        return ScanResult(path, "", 0, "unknown", [], 0, "Safe", [], error=str(exc))

    if size > config.max_file_size:
        return ScanResult(
            path, "", size, "unknown",
            [{"code": "skipped_large", "description": "File skipped due to size"}],
            0, "Safe", ["skipped_large"],
        )
```

A file the scanner could not `stat()`, and a file past the size limit, both came
back with `severity="Safe"` and `score=0`. The severity vocabulary had no way to
say *"I did not look"*: `SEVERITY_BANDS` in `scanner/heuristics.py` offered only
`Safe`, `Caution`, `Suspicious`, `High`. A teacher scanning a folder saw a green
row and moved on.

The same failure appeared throughout the detectors, as silence rather than as a
wrong label:

```python
    except zipfile.BadZipFile:
        pass                       # scanner/detectors/zip_rules.py:analyze_zip
```

```python
    except zipfile.BadZipFile:
        # Not OOXML .docx/.pptx/.xlsx; could be legacy binary. v0.1: skip deep OLE parse.
        pass                       # scanner/detectors/office_rules.py:analyze_office
```

A corrupt archive, an encrypted archive, a legacy `.doc`, a `.rar`, a `.7z`, an
`.rtf` — every one of these produced zero findings, and zero findings meant
`Safe`. Measured on the corpus, v0.2.0 returned `Safe / score 0` for
`broken_upload.zip`, `archive_password_protected.zip`, `coursework.7z` and
`essay.rtf`. An archive nobody can open is exactly where someone puts a file
they do not want looked at.

### 2. The scoring model could not be defended, and saturated immediately

`scanner/heuristics.py` was a table of integers with no stated origin:

```python
WEIGHTS: Dict[str, int] = {
    "exe_in_zip": 40,
    "zip_vba_project": 35,
    ...
}

def calculate_score(findings):
    score = 0
    for finding in findings:
        code = finding.get("code") or finding.get("rule", "")
        weight = WEIGHTS.get(code or "", 5)
        score += weight
    score = min(score, 100)
```

Four consequences, all reproduced:

**One fact was counted several times.** The old ZIP detector and the old Office
detector both looked for `vbaProject.bin`, and the extension check fired too.
`office_with_macro.docm` produced four findings for one macro —
`zip_vba_project` (35) + `office_macro_extension` (30) + `office_vba_project`
(45) + `office_auto_actions_hint` (15) = 125, capped to 100. The same on a PDF,
where `/JS` and `/JavaScript` were counted once by the token scanner and again by
the rule module:

```
pdf_javascript.pdf: score=100 severity=High issues=5
    pdf_token         PDF contains token /JAVASCRIPT
    pdf_token         PDF contains token /JS
    pdf_token         PDF contains token /OPENACTION
    pdf_auto_actions  Document defines automatic actions (OpenAction/AA).
    pdf_javascript    Embedded JavaScript detected.
```

**Repetition was free.** Nothing capped a code's contribution, so a hostile
archive with 900 executable members scored the same 100 as one with a single
`.exe` — the score carried no more information than a boolean.

**Weak signals accumulated into an emergency.** `url` was worth 5 points and
there was no cap on how many URLs could be extracted. A bibliography:

```
20-link text file -> score 100, severity "High"
```

A student's reference list was labelled with the tool's most severe verdict.

**Severity and certainty were the same axis.** "This document definitely contains
a macro" and "this JPEG might have something after the end marker" both became
"+n points", so the report could not distinguish a fact from a guess.

### 3. Detector defects, per format

**Every well-formed PNG was flagged.** `detectors.detect_image_appended_data`
found `IEND` and then treated everything after the four-byte chunk *type* as
appended data — forgetting the four-byte CRC that every valid PNG has there:

```python
        if b"IEND" in data:
            index = data.rfind(b"IEND")
            trailer = data[index + 4 :]
            if trailer.strip(b"\x00"):
                return _issue("image_trailing_data", "PNG file contains data after IEND chunk")
```

Reproduced on a minimal, entirely valid PNG whose last eight bytes are
`49454e44 ae426082` (`IEND` + CRC): it returns
`{'code': 'image_trailing_data', 'description': 'PNG file contains data after IEND chunk'}`.
Every diagram, screenshot and scanned worksheet a class submits carries this
finding.

**Every real Word document was flagged.** `office_rules.analyze_office` treated
the presence of `settings.xml` as an auto-behaviour hint:

```python
            if any("settings.xml" in name for name in names):
                findings.append({"rule": "office_auto_actions_hint", "severity": "medium", ...})
```

`word/settings.xml` is present in every `.docx` Word has ever written. On the
corpus, the clean control document `clean_report.docx` scored 15 for this alone.

**Any `.js` in an archive was "an executable".** `SUSPICIOUS_EXECUTABLE_SUFFIXES`
included `.js` and `.dll`, and `detect_zip_contents` flagged each matching member
with `exe_in_zip` at 40 points. A web-development submission:

```
website_project.zip  (index.html, style.css, js/app.js, js/vendor/jquery.min.js)
  -> score 80, severity "High"
     exe_in_zip: js/app.js
     exe_in_zip: js/vendor/jquery.min.js
```

For a computing class, the tool condemned the assignment it was given.

**PDF tokens straddling a read boundary were missed.** `detect_pdf_risks` read
4096-byte chunks and carried only ten bytes across the boundary, while searching
for tokens up to thirteen bytes long:

```python
                combined = (buffer + chunk).upper()
                for token in PDF_TOKENS:      # includes b"/EMBEDDEDFILE" (13 bytes)
                    ...
                buffer = combined[-10:]
```

Reproduced by placing `/EmbeddedFile` across offset 4096:

```
/EmbeddedFile MISSED when 11 of its 13 bytes precede the 4096-byte boundary
/EmbeddedFile MISSED when 12 of its 13 bytes precede the 4096-byte boundary
```

**The JPEG check was a single equality test.** `image_rules.analyze_image` only
asked whether the whole file ended in `FFD9`. Any appended payload that itself
happened to end in those bytes passed, and the parallel check in
`detectors.detect_image_appended_data` only read the last 8 KB — so it found the
end marker precisely when the appended payload was *small*, and lost it when the
payload was large. On the corpus, `image_large_appended.jpg` (600 KB of data
after the end marker) scored 15 and was labelled `Safe`.

**Nothing looked at content versus name.** A Windows PE renamed `holiday.jpg`
was caught only by the two-byte `MZ` check, worth 50 points — `Suspicious`, not
`High`. A PE renamed `report.docx` likewise. There was no extension-versus-magic
comparison at all.

**Archives were checked for almost nothing that matters.** There was no path
traversal check, no compression-ratio check, no member cap, no nesting depth
limit, no encryption detection. A ZIP whose member is `../../autorun.txt`, and a
48 KB ZIP that unpacks to 48 MB, both came back `Safe` with score 0. See the
corpus table under *Baseline measurements*.

### 4. Nothing was bounded

Each of the four rule modules began the same way:

```python
def analyze_zip(f: BinaryIO, strict: bool = False) -> List[Dict]:
    data = f.read()
```

`analyze_pdf`, `analyze_office` and `analyze_image` were identical. With the
default `max_file_size` of 100 MB and the default four threads, this is up to
400 MB of attacker-chosen bytes resident at once, before any regex work over
them. Measured on four 64 MB files at the default thread count:

```
v0.2.0  peak RSS 281.5 MB
0.3.0   peak RSS  26.7 MB
```

There was also no member cap when walking a central directory, no recursion
limit (there was no recursion at all, which is a different bug), and no cap on
how many findings one file could produce.

### 5. Symlinks were followed, and hung the scanner

`utils.iter_directory_files` yielded symlinked files, and `sha256_stream` opened
them. A submission archive extracted with links preserved — or a student who
simply included one — was enough:

```
scanning a folder containing a symlink -> /dev/zero
  ... killed at the 20-second timeout, still hashing
```

The scan never finished and never reported anything.

### 6. Filename deception was almost entirely missed

`detect_double_extension` handled `essay.pdf.exe`. Nothing handled:

- right-to-left override characters (`invoice‮gpj.exe` renders as
  `invoiceexe.jpg`) — v0.2.0 scored this 50, `Suspicious`, and only because of
  the `MZ` header, not the name;
- zero-width and other invisible characters in names;
- NUL bytes in archive member names (there was a `zip_nul_byte` code in the
  weight table, but at 25 points it could not reach `High` on its own);
- version-like fragments producing false double-extension alarms
  (`report.v2.final.docx`).

### 7. Quarantine destroyed student work on a name collision

```python
def move_to_quarantine(src: Path, dest_dir: Path, *, sha256: str | None = None) -> Path:
    utils.ensure_directory(dest_dir)
    destination = dest_dir / src.name
```

No collision handling. `Path.rename` overwrites on POSIX. Reproduced:

```
quarantine alice/assignment.docx, then bob/assignment.docx
  files in quarantine: ['assignment.docx', 'assignment.docx.meta.json']
  content of assignment.docx now: b'BOB WORK'
```

Alice's submission is gone, and so is the metadata record that it ever existed.
Thirty students, one assignment name — this is the normal case, not the edge
case.

Two further problems: the quarantined copy kept its original extension, so a
double-click still handed it to Word or the shell; and `set_read_only` cleared
write bits but not execute bits.

### 8. Reporting

- **The console report emitted student-controlled bytes raw.**
  `render_console_table` wrote the path directly. A file named with a carriage
  return and an ANSI erase-line sequence rewrites its own row:

  ```
  'essay\x1b[2K\rSCAN COMPLETE: all files safe.txt | High | 100 | pe_header'
  ```

  Rendered in a terminal, the `High` row erases itself and prints a reassuring
  line instead.

- **The HTML report needed JavaScript to be usable**, and its main call to
  action was a button that copied a shell command
  (`python -m scanner quarantine "..." --dest ./quarantine`) to the clipboard for
  the teacher to paste into a terminal. HTML escaping itself was done correctly.

- **The report said what was found but not what it meant.** Findings rendered as
  `pdf_token — PDF contains token /AA`. There is no action a non-technical
  reader can take from that, and the project's entire premise is a
  non-technical reader.

- **There was no folder-level answer.** The output was a per-file table. The
  question a teacher has — *which of these thirty do I not open* — had to be
  reconstructed by eye.

### 9. Exit codes and CLI

`main.emit_results` mapped severities to exit codes as
`{"Safe": 0, "Caution": 1, "Suspicious": 1, "High": 2}`, so `Suspicious` — the
band containing a real Windows executable named `Assignment.pdf.exe`, scored 65 —
was indistinguishable from `Caution` to any script.

Worse, a mistyped path was silently successful:

```
$ python -m scanner scan /tmp/does-not-exist-typo
WARNING scanner.main: Target /tmp/does-not-exist-typo does not exist
INFO scanner.main: No files scanned
exit code = 0
```

Exit 0 from a scanner means "clean". A typo in a path produced the same signal as
a clean folder.

### 10. The GUI and the packaging

`scanner/gui.py` imported PySimpleGUI at module scope and `requirements.txt`
pinned `PySimpleGUI==4.60.5.1`. That pin is itself the residue of a problem: the
immediately preceding commit in this repository is

```
f26df55 fix(deps): bump PySimpleGUI pin to 4.60.5.1 (4.60.5 was yanked from PyPI)
```

Because `pip install -r requirements.txt` was the *only* install step in both
workflows, an unavailable PySimpleGUI does not merely break the window. It breaks
the install, which means `ruff`, `mypy` and `pytest` are never installed, which
means CI cannot run at all. The scanner core needed nothing but the standard
library, but the project made a GUI toolkit mandatory to install it.

`scripts/build_pyinstaller.sh` and `.ps1` built from `scanner/gui.py` with
`--windowed`, so the produced binary had no working command line. The release
workflow shipped the artefacts with no checksum and no statement that they were
unsigned.

### 11. The test suite tested the wrong direction

Eleven tests, in seven modules. Ten of them fed a hand-made input to one detector
function and asserted that a rule name came back: a ZIP containing
`homework.png.exe`, a PDF containing `/OpenAction /JavaScript`, a ZIP containing
`vbaProject.bin`, twenty bytes after `IEND`, plus two tests that the weight table
adds up. The eleventh was the only integration test:

```python
def test_scan_examples_benign_samples():
    sample_dir = Path(__file__).resolve().parent.parent / "examples" / "benign_samples"
    results = scan(sample_dir, ScanConfig(max_file_size=5_000_000, threads=2))
    assert results
    for result in results:
        assert result.severity in {"Safe", "Caution"}
        assert result.score < 50
```

It scanned three benign files produced by `examples/generate_benign_samples.py`
(a text file, a 1×1 PNG, a minimal `.docx`) and asserted that none of them was
flagged. There was **no end-to-end test anywhere that a dangerous file produced a
dangerous verdict.** Every deletion in section 3 above — remove the ZIP detector,
remove the PDF detector, return `[]` from everything — leaves this suite green.

`scanner/reporters.py`, `scanner/quarantine.py`, `scanner/main.py` and
`scanner/gui.py` had no tests at all: no test module imported them.

### 12. The tooling configuration was not doing what it said

**`ruff` was running a much narrower rule set than the project declared.**
`pyproject.toml` said:

```toml
[tool.ruff.lint]
select = ["E", "F", "B", "I"]
```

but a root `ruff.toml` also existed, containing only `line-length` and
`target-version`. Ruff's discovery prefers `ruff.toml` over `pyproject.toml` and
does not merge them, so the `select` list never applied. Confirmed:

```
$ ruff check scanner tests                          # as configured
All checks passed!
$ ruff check --config pyproject.toml scanner tests  # as intended
5  E501  line-too-long
4  I001  unsorted-imports
Found 9 errors.
```

**`mypy` had two competing configs and used neither of the declared minimum
version.** `mypy.ini` (`python_version = 3.11`) and `setup.cfg` (`[mypy]`,
`python_version = 3.10`) both existed. `mypy -v` confirms `mypy.ini` won, so the
`setup.cfg` block was dead and type checking never ran at 3.10 — the minimum the
package claims to support and the version the CI matrix tested.

Both configs also set `ignore_missing_imports = True` globally, which silences
missing-stub errors for everything, not just the optional extras that needed it.

---

## What could not be checked, and why

Stated precisely, because a reader deciding whether to trust this tool should
know the shape of the hole.

| Claim | Status | Reason |
| --- | --- | --- |
| The PyInstaller binary builds | **Not verified** | `pyinstaller` is not installed and cannot be installed: `pypi.org` and `files.pythonhosted.org` both return HTTP 403 through this environment's egress proxy. No frozen binary was produced or run, at HEAD or now. |
| Behaviour on Windows | **Not verified** | Linux only. Everything about Windows extension hiding, SmartScreen, `.lnk` handling and path semantics is reasoned from the code, not observed. |
| Behaviour on macOS | **Not verified** | Linux only. Gatekeeper, quarantine xattrs and notarisation are unobserved. |
| The GUI window opens | **Not verified** | `import tkinter` fails here (`ModuleNotFoundError`), and there is no display. The Tk shell in `scanner/gui.py` has never been rendered in this environment. Its presentation logic was moved into `scanner/gui_model.py`, which has no Tk import and *is* tested — but that is the model, not the window. |
| PySimpleGUI 4.60.5.1 is absent from PyPI today | **Not verified** | `pip download PySimpleGUI==4.60.5.1` reports `from versions: none`, but every PyPI request from this environment returns 403, so "unavailable" cannot be distinguished from "blocked". What *is* established from the repository's own history is that the previous pin, 4.60.5, was yanked (commit `f26df55`). |
| The optional `python-magic` and `yara-python` paths | **Not verified** | Neither package is installable here. The code paths that use them were read, and the no-YARA and no-rules branches were exercised, but no real YARA rule was ever compiled or matched. |
| File permission enforcement in quarantine | **Partly verified** | The quarantine tests run as root in this environment, where POSIX permission bits are not enforced. One test (`test_scanner_core.py:58`) skips itself for exactly this reason and is reported as skipped, not passed. |
| CI itself | **Not verified** | GitHub Actions was never executed. The workflow YAML was read and the individual commands it runs were reproduced locally; the matrix (macOS, Windows, Python 3.10/3.12) was not. |

---

## Baseline measurements

All numbers below were produced by running the tools in this environment:
`pytest 9.0.3`, `ruff 0.15.11`, `mypy 1.20.2` on CPython 3.11.15. Note these are
substantially newer than the versions v0.2.0 pinned (`ruff 0.6.9`,
`mypy 1.11.2`), so the HEAD lint and type results are "clean under a newer tool",
which is if anything a stronger result than the project could have claimed.

HEAD was measured in a clean `git worktree` at `ad1b6f3`; the current tree was
measured in place.

| Measurement | HEAD (v0.2.0) | Current (0.3.0) |
| --- | --- | --- |
| `pytest -q` | `11 passed` | `117 passed, 1 skipped` (118 collected) |
| Test modules | 7 | 6 |
| Modules with any test coverage | `detectors`, `heuristics`, `scanner_core` | every module except the Tk widget layer in `gui.py` and the six-line `__main__.py` shim |
| `ruff check scanner tests` | `All checks passed!` | `All checks passed!` |
| `ruff check --config pyproject.toml scanner tests` | `Found 9 errors` (5 `E501`, 4 `I001`) | n/a — `ruff.toml` deleted, `pyproject.toml` is the only config |
| `ruff check scanner tests examples` (CI command) | not the CI command at HEAD | `All checks passed!` |
| `mypy scanner` | `Success: no issues found in 14 source files` | `Success: no issues found in 19 source files` |
| Config files for two tools | 4 (`pyproject.toml`, `ruff.toml`, `mypy.ini`, `setup.cfg`) | 1 (`pyproject.toml`) |
| `scanner/**/*.py` lines | 1,434 | 5,161 |
| `tests/**/*.py` lines | 173 | 1,107 |
| Distinct finding codes | 24 weight-table entries | 68 in code, each with plain-English text |
| Detection regression gate | none | `scripts/check_corpus.py`, 31 samples |
| Peak RSS, four 64 MB files, 4 threads | 281.5 MB | 26.7 MB |
| Corpus: risky samples labelled `Safe` | 11 of 22 | 0 of 22 |
| Corpus: clean samples given spurious findings | 3 of 9 (`clean_diagram.png`, `clean_report.docx`, `clean_essay.txt`) | 0 of 9 |

### The corpus comparison

The fourteen samples where the two versions disagree materially. v0.2.0 numbers
are its own `severity`/`score`; 0.3.0 numbers are its verdict. The remaining
seventeen agree in direction, though v0.2.0 placed four of them one band low
(`Assignment.pdf.exe`, `invoice‮gpj.exe`, `image_is_really_a_program.jpg` and
`office_renamed_program.docx` all landed in `Suspicious`, which its own exit-code
map treated the same as `Caution`).

| sample | v0.2.0 | 0.3.0 |
| --- | --- | --- |
| `archive_path_traversal.zip` | **Safe 0** | DO NOT OPEN |
| `archive_zip_bomb_shape.zip` | **Safe 0** | DO NOT OPEN |
| `office_remote_template.docx` | **Safe 15** | DO NOT OPEN |
| `office_dde_field.docx` | **Safe 15** | DO NOT OPEN |
| `image_large_appended.jpg` | **Safe 15** | DO NOT OPEN |
| `pdf_appended_payload.pdf` | **Safe 0** | REVIEW WITH CAUTION |
| `archive_password_protected.zip` | **Safe 0** | REVIEW WITH CAUTION |
| `office_embedded_object.docx` | **Safe 15** | REVIEW WITH CAUTION |
| `broken_upload.zip` | **Safe 0** | COULD NOT INSPECT |
| `coursework.7z` | **Safe 0** | COULD NOT INSPECT |
| `essay.rtf` | **Safe 0** | COULD NOT INSPECT |
| `clean_diagram.png` | **Safe 15 — false positive** | LIKELY SAFE |
| `clean_report.docx` | **Safe 15 — false positive** | LIKELY SAFE |
| `clean_essay.txt` | **Safe 5 — false positive** | LIKELY SAFE |

---

## Residual limitations of the current tree

These are not v0.2.0 defects. They are things the 0.3.0 code still does not do,
recorded here so the audit is not a sales document.

- **A `.js` file inside an archive still produces DO NOT OPEN.**
  `archive_executable_member` is `HIGH` severity, and Rule 2 blocks on any
  high-severity finding at high *or medium* confidence. The
  `_is_code_assignment_shaped()` heuristic in `scanner/detectors/archive.py`
  lowers the confidence to `MEDIUM` for paths like `src/app.js` — but medium is
  still decisive, so the verdict is unchanged. Verified:

  ```
  lab3.zip containing src/app.js
    -> DO_NOT_OPEN  [('archive_executable_member', 'high', 'medium')]
  ```

  A computing teacher will need `--zip-rules off`, or will need this rule
  softened. The finding text says so, which is better than v0.2.0 managed, but
  the verdict is still wrong for that audience.

- **No `.rar`, `.7z`, `.tar`, `.gz` or `.rtf` inspection.** These are reported as
  `COULD NOT FULLY INSPECT` with an explanation, which is honest, but the
  contents are genuinely unexamined.

- **Legacy OLE (`.doc`, `.xls`, `.ppt`) analysis is shallow.** The compound-file
  directory is read for macro storage names; the streams themselves are not
  parsed.

- **`defusedxml` is optional.** Without it, OOXML relationship parsing falls back
  to a byte-level regex scan. This is deliberate — stdlib `ElementTree` is not
  safe on untrusted input and is never used — but the byte scan is less precise
  than real parsing. Both paths were exercised (see the changelog's verification
  section); they produced identical verdicts on the corpus, which is evidence,
  not proof.

- **This is not antivirus.** There is no signature database and no behavioural
  analysis. `LIKELY SAFE TO REVIEW` means "nothing matched the checks this tool
  performs", and the report says exactly that.
