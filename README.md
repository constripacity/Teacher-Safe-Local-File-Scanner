<h1 align="center">Teacher-Safe Local File Scanner</h1>

<p align="center">
  <strong>Point it at a folder of student submissions. It tells you which ones not to open, and why — in plain English.</strong>
</p>

<p align="center">
  Runs entirely on your machine · never opens or runs the files it checks · no account, no upload, no API key
</p>

<p align="center">
  <a href="#30-second-start">Quickstart</a> ·
  <a href="#what-it-actually-checks">What it checks</a> ·
  <a href="#how-a-verdict-is-decided">How verdicts work</a> ·
  <a href="#what-this-is-not">Limits</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

```
  15 of 29 files should not be opened. 4 more need a closer look.

   ✖ 15 DO NOT OPEN    ! 4 CAUTION    ? 1 NOT CHECKED    ✓ 9 LIKELY SAFE

  FILE                            VERDICT        WHY
  ------------------------------------------------------------------------------
  image_is_really_a_program.jpg   ✖ DO NOT OPEN  File contains a program, whatever it is named
  invoice<U+202E>gpj.exe          ✖ DO NOT OPEN  Filename uses a right-to-left override character
  office_remote_template.docx     ✖ DO NOT OPEN  Document links out to a remote template
  office_with_macro.docm          ✖ DO NOT OPEN  Document contains a macro project
  archive_path_traversal.zip      ✖ DO NOT OPEN  Archive entry escapes its own folder
  pdf_launch_action.pdf           ✖ DO NOT OPEN  PDF tries to launch another program
  links_suspicious.txt            ! CAUTION      Link uses a lookalike internationalised domain
  broken_upload.zip               ? NOT CHECKED  Archive could not be opened
```

> **To add a screenshot:** run `teacher-safe-scan scan examples/benign_samples --report-html demo.html`,
> open `demo.html`, and drop the image at `docs/report.png`. The corpus is
> committed, so anyone can reproduce exactly the output above.

## Why this exists

A teacher gets thirty files through the LMS. One of them is a `.docm` with a
macro. Existing tools do not help with that specific problem:

| Tool | What it gives you |
| --- | --- |
| **Antivirus** | A verdict on *known* malware. Silence on a novel macro document. |
| **[Dangerzone](https://github.com/freedomofpress/dangerzone)** | A sanitised copy of one file. Tells you nothing about what was in it, and can't take a folder. |
| **[oletools](https://github.com/decalage2/oletools)**, pdfid, YARA | Excellent analyst output. Assumes you already know what `VBA_PROJECT` means. |
| **VirusTotal-backed CLIs** | Great results — after uploading student work to a third party. |
| **This** | One page. One row per submission. Worst first. A sentence per finding you could forward to a parent. |

The unit of work here is **the folder**, not the file. That is the whole product.

## 30-second start

No install, no dependencies — the scanner core is pure standard library.

```bash
git clone https://github.com/constripacity/Teacher-Safe-Local-File-Scanner
cd Teacher-Safe-Local-File-Scanner

python examples/generate_benign_samples.py      # 28 harmless files that trip every detector
python -m scanner scan examples/benign_samples  # see the output above
```

Then point it at real work:

```bash
python -m scanner scan ~/Downloads/period-3-submissions --report-html report.html --open-report
```

Prefer a window? `python -m scanner gui` (needs `tkinter`; on Debian/Ubuntu:
`sudo apt install python3-tk`).

Install it properly if you want the `teacher-safe-scan` command on your PATH:

```bash
pip install -e .
teacher-safe-scan scan ~/Downloads/submissions
```

## What it actually checks

Every check is **static**. Files are read as bytes. No macro runs, no PDF is
rendered, no archive is extracted, no image is decoded.

<details open>
<summary><strong>Archives</strong> (.zip, .jar, .apk)</summary>

- entries that unpack **outside** the extraction folder (`../`, absolute paths, drive letters, UNC)
- executables and scripts inside the archive
- members disguised with a double extension (`essay.pdf.exe`)
- right-to-left overrides, zero-width and NUL characters in member names
- password-protected entries — reported as *not checked*, never as clean
- decompression-bomb shape: per-entry ratio and total unpacked size
- nested archives, opened to a bounded depth; anything deeper is reported as unchecked
</details>

<details>
<summary><strong>Office documents</strong> (.docx/.xlsx/.pptx, .docm/.xlsm/.pptm, legacy .doc/.xls)</summary>

- macro projects (`vbaProject.bin`), and whether they are signed
- **remote template injection** — the `attachedTemplate` external relationship
- DDE / DDEAUTO field codes
- ActiveX controls and embedded OLE objects
- legacy compound-file macro storage
- a file whose container does not match its extension

Relationship XML is parsed with `defusedxml` when installed, and by a byte scan
when it is not — never by stdlib ElementTree, which is not safe on hostile input.
</details>

<details>
<summary><strong>PDFs</strong></summary>

- `/Launch` actions
- JavaScript (`/JS`, `/JavaScript`) — counted once, not twice
- `/OpenAction` and `/AA` automatic actions
- embedded file attachments
- encryption (reported as *not fully checked*)
- content appended after the final `%%EOF`
- a PDF header that is not at byte zero
</details>

<details>
<summary><strong>Images</strong> (.png, .jpg, .gif)</summary>

- a program renamed to `.jpg` (content is checked, not the name)
- **polyglots** — a real ZIP, PE or PDF hidden after the image terminator
- large appended payloads, found however far from the end they are
- oversized metadata chunks
- impossible internal chunk lengths
</details>

<details>
<summary><strong>Every file</strong></summary>

- extension vs. real content mismatch, by magic bytes
- double extensions and executable extensions
- right-to-left override and invisible characters in the filename
- shortened, raw-IP and punycode links inside text files
- SHA-256, and identical files submitted more than once
</details>

## How a verdict is decided

Four verdicts, and **"could not check" is never rounded down to "safe"**:

| | Meaning |
| --- | --- |
| ✓ **LIKELY SAFE TO REVIEW** | Nothing matched. Not a guarantee. |
| ! **REVIEW WITH CAUTION** | Something is worth a human look before opening. |
| ✖ **DO NOT OPEN — CONTACT IT** | A high-severity indicator matched with usable confidence. |
| ? **COULD NOT FULLY INSPECT** | Encrypted, too large, corrupt, or beyond a limit. **Unchecked ≠ clean.** |

The verdict comes from four stated rules, not from summing opaque numbers.
Severity ("how bad if true") and confidence ("how sure are we") are tracked
separately, so *"this definitely has a macro"* and *"this might have an appended
payload"* are never treated alike. Full model, including the exact rules and the
per-finding-code cap that stops one hostile archive inflating a score:
**[docs/SCORING.md](docs/SCORING.md)**.

Every finding carries five things, and the report shows all of them:

```
[HIGH · high confidence]  Archive entry escapes its own folder

  One of the files inside this archive is set to unpack somewhere
  outside the folder you unzip it into.

  Why this matters   This is how an archive overwrites a file elsewhere on
                     the computer the moment it is extracted. There is no
                     legitimate reason for a student submission to do this.
  What to do         Do not extract this archive. Send it to IT.
  Evidence           ../../autorun.txt
  Detected by        archive
```

## Reports

```bash
teacher-safe-scan scan ./submissions \
  --report-html report.html \      # self-contained: no scripts, no network requests
  --report-json report.json        # for scripting, or re-render later with `report`
```

The HTML report groups files worst-first, opens the flagged ones by default,
prints cleanly, and can be forwarded to IT as a single file. It contains **no
JavaScript and makes no network requests** — a report about untrusted files
should not itself phone anywhere.

## Quarantine — and getting files back

```bash
teacher-safe-scan scan ./submissions --quarantine-dir ./quarantine
teacher-safe-scan quarantine-list --dest ./quarantine
teacher-safe-scan restore 3f9a21c40b8e --dest ./quarantine
```

- **Nothing is ever deleted.** Quarantine moves; restore moves back.
- Stored copies get a `.quarantined` suffix and lose their execute bits, so a
  double-click hands them to nothing.
- Two students submitting `assignment.docx` produce two distinct entries. No
  overwrite, no data loss.
- Every move is written to an append-only JSONL manifest with the SHA-256 before
  and after, so a restore is verified and provable.

## Command reference

| Command | What it does |
| --- | --- |
| `scan <paths…>` | Scan files or folders and print the triage table |
| `scan … --watch` | Re-scan only files that appear or change |
| `scan … --quarantine-dir DIR` | Move blocked files aside (nothing deleted) |
| `report <json> --html <out>` | Re-render a saved report |
| `quarantine <file> --dest DIR` | Move one file into quarantine |
| `quarantine-list --dest DIR` | List what is in quarantine |
| `restore <id> --dest DIR` | Move a file back out, hash-verified |
| `gui` | Open the desktop window |
| `make-samples` | Write the benign test corpus |

Exit codes: `0` nothing found · `1` needs attention · `2` do not open · `3`
scanner error · `4` usage error. Useful in a script:

```bash
teacher-safe-scan scan ./inbox || echo "something needs a look"
```

Optional extras, none required: `pip install -e ".[xml]"` (hardened XML),
`".[yara]"` (`--yara-rules your.yar`).

## What this is not

- **Not antivirus.** No signature database, no known-malware detection. Run it
  *alongside* your school's endpoint protection, never instead of it.
- **Not a guarantee.** "Likely safe" means nothing matched the checks in this
  tool. A novel technique this tool does not model will come back clean.
- **Not a sanitiser.** It does not produce a safe copy. For that, use
  [Dangerzone](https://github.com/freedomofpress/dangerzone) — the two compose
  well: triage here, sanitise there.
- **Not for offensive use.** It detects; it never builds, packs, or executes.

## Privacy

Nothing leaves your machine. There is no telemetry, no update check, no network
code of any kind in the scanner. Student work is student data, and it stays on
the laptop it arrived on.

## Development

```bash
pip install -e ".[dev]"
pytest -q                        # 114 tests
ruff check scanner tests examples
mypy scanner
python scripts/check_corpus.py   # detection regression: every sample must land where it should
```

`scripts/check_corpus.py` is the test that matters most. It asserts both
directions: every hostile-shaped sample is caught, **and** every clean sample
stays clean. A triage tool that cries wolf gets uninstalled.

Building a standalone binary (unsigned — see the script's own warning):

```bash
pip install -e ".[build]"
python scripts/build_binary.py
```

## Contributing

New detectors are very welcome, especially with a benign sample in
`examples/generate_benign_samples.py` and a row in `scripts/check_corpus.py`.
Start with [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Please read
[SAFETY.md](SAFETY.md) before opening a PR — this project stays defensive.

## License

MIT — see [LICENSE](LICENSE).
