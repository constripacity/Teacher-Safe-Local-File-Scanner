# The next 18 commits

## Where this leaves off

v0.3.0 is a working folder-triage tool. `teacher-safe-scan scan <folder>` walks a
directory, opens each file once, dispatches by sniffed content type, and prints a
worst-first table under a plain-English headline; the four-verdict model in
`scanner/verdict.py` is tested rule by rule, `COULD NOT FULLY INSPECT` is never
rounded down to safe, and `scripts/check_corpus.py` asserts both directions over
28 generated samples. What is **not** verified is the part a teacher touches
first: the Tkinter window in `scanner/gui.py` has never been executed by anyone,
because `tkinter` is absent from the environment this revival was built in
(`gui_model.py` is unit tested; `gui.py` is not, and CI has no job that opens a
window). The PyInstaller binary has likewise never been built or run — the spec
and `scripts/build_binary.py` are written but unexercised locally, and the whole
revision is still an uncommitted working tree, so no CI run has ever seen it.
Three defects were found by reading and are not yet fixed: `.rar`, `.7z`,
`.tar.gz`, `.tar` and `.rtf` submissions receive **no** content analysis at all
and come back `LIKELY SAFE TO REVIEW` (verified — this is the same class of bug
the revival release fixed for oversized files); every structurally clean PDF over
8 MB is reported `COULD NOT FULLY INSPECT` because `iter_windows` bounds total
bytes streamed by `max_read_bytes` (verified with a 12.1 MB file); and
`teacher-safe-scan make-samples` will fail on any pip-installed copy, because
`handle_make_samples` imports `examples.generate_benign_samples` while
`pyproject.toml` packages only `scanner*`. `SAFETY.md` links a `SECURITY.md` that
does not exist, `CONTRIBUTING.md` still tells contributors to install a
`requirements-optional.txt` that was deleted, and `--pdf-rules strict` is accepted
by the CLI and does nothing.

The ordering below is: verify what could not be verified, then make the thing
installable, then build the LMS-ingestion path that is the actual wedge, then
detector depth, then the rest. Commits 03 and 17 are defect fixes sitting inside
the verification and tail blocks respectively; if anything slips, pull those two
forward rather than shipping a signed binary that carries them.

---

## 01 — test(gui): open the window in CI and assert what it renders

**Goal** Execute `scanner/gui.py` for the first time, on all three platforms, and
leave behind a test suite that fails when the window breaks.

**Why it matters** `docs/ARCHITECTURE.md` says `gui.py` "is exercised by hand".
It has not been exercised by anyone. Every claim in the README about the desktop
window is currently unverified, and the window is the entry point for the user
this project is named after.

**Files**
- `tests/test_gui_window.py` — new
- `.github/workflows/ci.yml` — a `gui` job, and `python3-tk` + `xvfb` on the Linux runner
- `pyproject.toml` — register a `gui` marker under `[tool.pytest.ini_options]`
- `scanner/gui.py` — only what the first run forces (keep fixes in 02)

**Implementation** Gate the module with `tk = pytest.importorskip("tkinter")` and
a `try: root = tk.Tk() / except tk.TclError: pytest.skip("no display")`. Never
call `mainloop()`; construct `ScannerWindow(root)`, then drive it with
`root.update()` and manual `_drain_queue()` polls until `self._summary` is set.
Reuse the existing `corpus` fixture from `tests/conftest.py` so the expected six
rows and their verdicts are already pinned by `test_scanner_core.py`.
Monkeypatch `filedialog.asksaveasfilename` and `messagebox.*` — a test that
blocks on a modal dialog hangs CI forever. On Ubuntu, `setup-python` builds do
ship `tkinter`, but the runner has no X server, so wrap the job in `xvfb-run -a`;
macOS and Windows runners need neither. Note that `addopts` already carries
`--strict-markers`, so the `gui` marker must be registered or every gui test
errors on collection.

**Tests** Window constructs without raising. `_start_scan` against the corpus
populates the Treeview with six rows, worst-first, each tagged with its verdict
slug. Selecting each row leaves `self.detail` non-empty and containing the
finding's `plain` text. `_save_html` and `_save_json` write real files.
`_copy_summary` puts `summarise_for_email` output where `root.clipboard_get()`
can read it. `_quarantine` with a monkeypatched `askdirectory` moves exactly the
`DO NOT OPEN` files and no others.

**Depends on:** nothing

**Risk** Low for the codebase, moderate for CI stability: Tk tests are flaky when
they race the event loop. Keep every assertion behind an explicit `root.update()`
and never sleep. If the macOS runner proves unreliable, run gui tests on Linux and
Windows only and say so in the workflow comment rather than marking them
`xfail`.

**Acceptance criteria**
- [ ] `pytest -m gui` passes locally under `xvfb-run` on Linux
- [ ] The `gui` job is green on ubuntu-latest, windows-latest and macos-latest
- [ ] Every public method of `ScannerWindow` is touched by at least one test
- [ ] No test can block on a dialog; the suite finishes in under 60 s per platform
- [ ] `docs/ARCHITECTURE.md` no longer says the GUI is exercised only by hand

**Scope** M

---

## 02 — fix(gui): the defects the first real run exposes

**Goal** Fix what commit 01 turns up, starting with the four failures that
reading the code predicts.

**Why it matters** A window that renders wrong, or silently loses the summary a
teacher just copied, is worse than no window: it is the part of the product that
gets demonstrated.

**Files**
- `scanner/gui.py` — `_copy_summary`, `_pick_files`, `_quarantine`, `_build`, `_start_scan`
- `scanner/gui_model.py` — `VERDICT_COLORS`, a dark-mode variant
- `tests/test_gui_window.py` — a regression test per fix

**Implementation** Four predicted defects, in order of user impact. (1)
`_copy_summary` calls `clipboard_clear()`/`clipboard_append()`; on X11 and on
Windows the clipboard is owned by the process, so the text vanishes when the
teacher closes the window to go and paste it. Follow the append with
`self.root.update()` and add a "Save summary as .txt…" fallback next to it. (2)
`_pick_files` joins the `askopenfilenames` tuple with `";"` and hands it to
`parse_dropped_paths`, which splits on `";"` — any path containing a semicolon is
silently split into two nonexistent paths. Keep the real list on the instance and
use the joined string for display only. (3) After `_quarantine` moves files, the
Treeview still lists them at paths that no longer exist and selecting one shows
stale detail; mark moved rows or re-scan. (4) `self.detail` is a bare `tk.Text`
with default colours while the ttk widgets follow the system theme, so it is a
white block in a dark window on macOS; set explicit foreground/background, and
give `VERDICT_COLORS` a dark variant since its four background colours are chosen
for a light ground. Also confirm on macOS whether `Treeview.tag_configure`
backgrounds actually apply under the `clam` theme — if they do not, colour is
still not the only channel, because `VERDICT_SYMBOL` is already in the row text.

**Tests** One regression test per fix. The clipboard case asserts the text
survives a `root.update()` cycle; the path case asserts a filename containing
`;` round-trips; the quarantine case asserts no row points at a missing file
after the move.

**Depends on:** 01

**Risk** Low. Confined to widgets and the presentation model, both of which now
have tests. The dark palette is a judgement call — pick contrast ratios that
still pass 4.5:1 against the dark ground and keep the symbols.

**Acceptance criteria**
- [ ] Copying the summary, closing the window, and pasting yields the summary
- [ ] A path containing `;` scans correctly from the file picker
- [ ] After quarantining, no visible row refers to a moved file
- [ ] The window is legible under both a light and a dark system theme on all three platforms
- [ ] Each fix has a test that fails on the parent commit

**Scope** M

---

## 03 — fix(detectors): unreadable container formats are unchecked, not safe

**Goal** Stop reporting `.rar`, `.7z`, `.tar`, `.tar.gz`, `.bz2` and `.xz`
submissions as `LIKELY SAFE TO REVIEW` when nothing has looked inside them.

**Why it matters** Verified: a file with RAR magic and a `.rar` name produces zero
findings and lands in the green column. `analyze_archive` is ZIP-only,
`_dispatch` runs it only when `detected == "zip"`, and `EXTENSION_EXPECTATIONS`
happily confirms that a `.rar` contains RAR — so the extension/content check
passes too and the file falls through every branch in silence. This is exactly
the defect class the revival release fixed for oversized files, and the corpus
never caught it because the corpus contains no RAR or 7z sample. It also
contradicts the project's loudest claim: "unchecked ≠ clean".

**Files**
- `scanner/detectors/base.py` — `UNINSPECTABLE_CONTAINER_TYPES`, a `ustar`-at-257 case in `sniff_magic`
- `scanner/scanner_core.py` — a branch in `_dispatch`
- `examples/generate_benign_samples.py` — three samples in `SAMPLES`
- `scripts/check_corpus.py` — three rows in `EXPECTED`
- `README.md`, `SAFETY.md` — state the limitation where the limits are stated

**Implementation** Add a frozen set of container types this scanner cannot read
(`rar`, `7z`, `gzip`, `bzip2`, `xz`, `tar`) to `base.py`, next to
`MAGIC_SIGNATURES` where a reviewer will find it. `sniff_magic` currently takes
only the head bytes and matches prefixes; add a `ustar` check at offset 257 so a
plain `.tar` stops sniffing as `unknown`. In `_dispatch`, after the existing
format branches, emit one finding when `detected` is in that set: severity `LOW`,
confidence `HIGH`, `inspection_incomplete=True`, so rule 1 in `decide()` carries
it to `COULD NOT FULLY INSPECT` without inventing a threat that has not been
observed. The `plain` text should say what it is: "This is a RAR archive. This
scanner can only look inside ZIP archives, so nothing inside this file has been
checked." The `action` should be the useful one: ask for a `.zip`, which the
scanner can read. Do not add RAR/7z parsing — that means a third-party
dependency reading hostile input, which is the opposite of this project's
posture.

**Tests** A unit test per format asserting `COULD_NOT_INSPECT` and the finding
code. A test that a ZIP is unaffected. Corpus rows expecting
`(UNKNOWN, "container_not_inspected")` for `archive_rar_shaped.rar`,
`archive_7z_shaped.7z` and `archive_tar_gz.tar.gz` — the samples only need
correct magic bytes and inert padding, which is consistent with how
`_encrypted_flag_zip` already fakes structure it cannot legitimately produce.

**Depends on:** nothing

**Risk** Low, but it moves files out of the green column, so a school that
routinely receives `.rar` coursework will see a new blue block. That is the
correct answer, and the finding text says so plainly. Keep it `LOW`/`HIGH` and
not `MEDIUM`, or two such files corroborate into `REVIEW WITH CAUTION` under
rule 3 and the tool starts crying wolf.

**Acceptance criteria**
- [ ] `.rar`, `.7z`, `.tar`, `.tar.gz`, `.bz2`, `.xz` all land in `COULD NOT FULLY INSPECT`
- [ ] A plain `.tar` sniffs as `tar`, not `unknown`
- [ ] Two such files in one folder do not escalate each other past caution
- [ ] `scripts/check_corpus.py` covers all three new samples
- [ ] README's "What this is not" states which archive formats can be opened

**Scope** M

---

## 04 — test(build): verify the frozen binary past `--version`

**Goal** Prove the PyInstaller build actually works, for every subcommand, before
anyone signs it.

**Why it matters** `release.yml` smoke-tests `--version`, `make-samples` and
`scan`. It does not test `report`, `quarantine`, `quarantine-list`, `restore`, or
`gui`, and nothing checks that `tkinter` was bundled at all — the spec's
`try: import tkinter` runs on the *build* machine, so a runner without Tk
silently produces a binary whose `gui` command can never work. Nobody has run
this binary.

**Files**
- `scripts/smoke_binary.py` — new
- `scripts/build_binary.py` — call it from `main()` instead of the inline `--version` check
- `.github/workflows/ci.yml` — the `build` job runs the smoke script
- `.github/workflows/release.yml` — the build matrix runs the same script

**Implementation** One script, taking the binary path, exercising the whole
`HANDLERS` table in `scanner/main.py`: generate the corpus, scan it and assert
exit code 2, write both reports, re-render the JSON through `report`, quarantine
a file, list it, restore it, and assert the restored bytes match. Then compare the
frozen binary's JSON report against one produced by `python -m scanner` over the
same corpus, ignoring `generated_at`, `duration_ms`, `roots` and absolute paths —
if a bundled resource diverges, the verdict counts diverge and this catches it.
For the GUI, launch `<binary> gui` with a deadline, assert the process is alive
after two seconds and then terminate it; on Linux run it under `xvfb-run`. Assert
`sys.platform == "darwin"`'s `argv_emulation=True` does not swallow arguments —
that flag has historically eaten the first argument on macOS. Record the binary
size and fail above a stated ceiling; a teacher downloading over a school network
is the constraint the spec cites for its `excludes` list.

**Tests** The script is the test. Add a `pytest` wrapper that runs it against
`dist/` when the binary exists and skips otherwise, so a local build is checked
the same way CI checks it.

**Depends on:** 01, 03

**Risk** Moderate CI time — three platforms building a onefile binary plus a full
smoke run. Cache PyInstaller's bootloader. The GUI-launch check is the flakiest
part; keep it to "process survives two seconds" rather than screenshotting.

**Acceptance criteria**
- [ ] Every subcommand in `HANDLERS` is exercised against the frozen binary
- [ ] The frozen binary's verdicts match the source tree's, file for file
- [ ] `<binary> gui` opens a window on all three platforms
- [ ] The build fails if `tkinter` was not bundled
- [ ] Binary size is printed in CI and fails above the agreed ceiling

**Scope** M

---

## 05 — fix(pkg): ship the corpus inside the package

**Goal** Make `teacher-safe-scan make-samples` work on a pip-installed copy.

**Why it matters** `handle_make_samples` does
`sys.path.insert(0, <parent of the scanner package>)` and then
`from examples.generate_benign_samples import write_samples`. In a wheel that
parent is `site-packages`, and `pyproject.toml` packages only `scanner*`, so the
import raises `ModuleNotFoundError` and the command dies with a traceback rather
than one of the CLI's own exit codes. It works from a git checkout and it works
in the frozen binary (the spec bundles the file as data and PyInstaller puts
`_MEIPASS` on `sys.path`), which is exactly why nobody has noticed. This must be
fixed before there is a PyPI release for anyone to hit it with.

**Files**
- `scanner/corpus.py` — new home for `SAMPLES`, `write_samples`, the `_png`/`_zip`/`_docx`/`_pdf` builders
- `examples/generate_benign_samples.py` — becomes a thin shim re-exporting from `scanner.corpus`
- `scanner/main.py` — `handle_make_samples` imports from the package, and the `sys.path` hack goes
- `scripts/check_corpus.py` — import from `scanner.corpus`
- `teacher-safe-scan.spec` — drop the now-unneeded `datas` entry

**Implementation** Move the module wholesale; keep the public names identical so
`check_corpus.py`'s `EXPECTED` and `tests/samples.py` need no edits. The shim at
`examples/generate_benign_samples.py` keeps the documented
`python examples/generate_benign_samples.py` command working and keeps
`ruff check scanner tests examples` meaningful. `examples/benign_samples/` stays
committed and unchanged — it is what makes the README's output reproducible.

**Tests** Add a test that imports `scanner.corpus` with the repository root
absent from `sys.path`, which is the condition a wheel install creates. The real
proof is in 06's installed-wheel smoke test.

**Depends on:** nothing

**Risk** Low. The only subtlety is `write_samples` writing a `README.md` into the
output directory; that behaviour must not change, because `check_corpus.py`'s
`EXPECTED` has a row for it.

**Acceptance criteria**
- [ ] `scanner/` has no import of `examples`
- [ ] `python examples/generate_benign_samples.py` still writes the same 28 files plus README
- [ ] `scripts/check_corpus.py` passes unchanged
- [ ] The spec no longer bundles a Python source file as data
- [ ] `pip install .` into a clean venv, then `teacher-safe-scan make-samples`, succeeds

**Scope** S

---

## 06 — feat(pkg): publish to PyPI with Trusted Publishing

**Goal** `pip install teacher-safe-local-file-scanner` works, and the release
workflow does it without a long-lived token.

**Why it matters** `release.yml`'s own release notes already tell users to
`pip install teacher-safe-local-file-scanner` as the alternative to an unsigned
binary. That instruction is currently false. For a teacher on a machine that has
Python but a blocked binary download, pip is the only route in, and the scanner
core needs nothing outside the standard library so the install is trivial —
once it exists.

**Files**
- `.github/workflows/release.yml` — a `pypi` job with `permissions: id-token: write`
- `pyproject.toml` — SPDX licence metadata, 3.13 classifier, `Intended Audience :: Education`, package data for `py.typed`
- `scanner/py.typed` — new, empty
- `scripts/smoke_wheel.py` — new

**Implementation** Build with `python -m build`, `twine check dist/*`, then
publish with `pypa/gh-action-pypi-publish` using OIDC Trusted Publishing so no API
token is stored in repository secrets — configure the publisher on PyPI against
this repository and the `release.yml` workflow before the first tag. Gate the job
on the existing `verify` job so nothing publishes without ruff, mypy, pytest and
`check_corpus.py` passing. Before publishing anything, install the built wheel
into a clean venv and run `scripts/smoke_wheel.py`: `teacher-safe-scan --version`,
`make-samples`, `scan` with both report formats, and the quarantine round-trip.
That script is what would have caught commit 05's bug. Switch
`license = { file = "LICENSE" }` to the SPDX `license = "MIT"` plus
`license-files`, which recent setuptools warns about. Ship `scanner/py.typed`,
since the package is fully annotated and `mypy scanner` is already in CI. Confirm
the distribution name is free on PyPI before tagging; the console script stays
`teacher-safe-scan` regardless.

**Tests** `scripts/smoke_wheel.py` runs in CI on every push against a locally
built wheel, not only at release time — the install path is the one that breaks
silently.

**Depends on:** 05

**Risk** Publishing is irreversible: a released version number can never be
reused. Publish `0.3.1` to TestPyPI first and install from it, then do the real
one. The `dependencies = []` line is load-bearing — if anything ever moves out of
`[project.optional-dependencies]`, the "no dependencies" claim in the README
becomes false and the bare-venv CI job is the thing that catches it.

**Acceptance criteria**
- [ ] A tag publishes to PyPI with no API token in repository secrets
- [ ] `pip install teacher-safe-local-file-scanner` into a clean venv gives a working `teacher-safe-scan`
- [ ] The installed package pulls in zero dependencies
- [ ] `scripts/smoke_wheel.py` runs on every CI push, not only on tags
- [ ] The release notes' pip instruction is now true

**Scope** M

---

## 07 — build(release): sign and notarise, or say plainly that we have not

**Goal** Produce macOS and Windows binaries that run without a security warning —
and make it impossible for the release notes to claim that before it is true.

**Why it matters** This is the largest single adoption blocker. A teacher on a
managed laptop who downloads the current binary gets Gatekeeper refusing to run
it on macOS and a SmartScreen warning on Windows. Telling a non-technical user to
run `xattr -d com.apple.quarantine`, as the release notes currently do, is asking
them to disable a security control in order to use a security tool.

**Costs, stated up front.** macOS requires Apple Developer Program membership at
USD 99/year; a Developer ID Application certificate cannot be obtained any other
way, and an organisation enrolment needs a D-U-N-S number and takes weeks.
Notarisation additionally needs an App Store Connect API key. Windows requires an
OV or EV code-signing certificate — roughly USD 200–600/year, with EV requiring a
hardware token or a cloud HSM; Azure Trusted Signing is currently the cheapest
route at around USD 10/month but needs an Azure subscription and a verified
organisation identity. Even after signing, SmartScreen reputation accrues with
download volume, so early users may still see a warning. Linux has no signing
authority at all. **If the school or maintainer will not fund these, do the
Sigstore half of this commit and leave the honest warning exactly as blunt as it
is now.**

**Files**
- `.github/workflows/release.yml` — signing steps in the macOS and Windows matrix legs, a Sigstore step for all three
- `scripts/build_binary.py` — read the signing state instead of hard-coding the "UNSIGNED" warning
- `teacher-safe-scan.spec` — `codesign_identity` and `entitlements_file` from the environment
- `docs/RELEASING.md` — new: key handling, rotation, what to do when a certificate expires
- `entitlements.plist` — new, minimal

**Implementation** macOS: import the `.p12` into a temporary keychain,
`codesign --timestamp --options runtime --sign "Developer ID Application: …"`,
then `xcrun notarytool submit --wait` with the API key and `xcrun stapler staple`.
Note that a PyInstaller `--onefile` binary notarises awkwardly because the
bootloader extracts to a temp directory at run time; if notarisation fights it,
ship a `--onedir` build inside a signed `.app` in a signed `.dmg` and keep the
onefile CLI binary as the unsigned developer artifact. Windows:
`signtool sign /fd sha256 /tr <rfc3161 url> /td sha256`. All three platforms:
`cosign sign-blob` with keyless OIDC, which costs nothing and gives a public
transparency-log entry for every artifact — do this even if nothing else here
gets funded. The important structural piece is that the release-notes body must
be generated from whether signing actually ran, not hand-written: a repository
variable gates both the signing steps and the wording, so an unsigned build
physically cannot ship notes claiming otherwise. `scripts/build_binary.py` reads
the same variable for its own printed warning. Do not claim reproducible builds;
PyInstaller output is not byte-reproducible and the SHA-256 in the release is a
download-integrity check, not a build attestation.

**Tests** A workflow-level check that the published macOS artifact passes
`spctl -a -vvv -t install` and that the Windows artifact's signature verifies with
`signtool verify /pa`. A test that the release-notes template renders the
unsigned warning when the signing variable is unset.

**Depends on:** 04

**Risk** High operational risk, low code risk. Secrets in CI: the `.p12` and its
password, the App Store Connect key, and the Windows certificate all become
repository secrets that can sign anything with this project's identity. Restrict
the signing job to a protected `release` environment with required reviewers.
Certificate expiry silently breaks releases a year later — put the expiry date in
`docs/RELEASING.md` and in a calendar.

**Acceptance criteria**
- [ ] A signed macOS binary runs on a clean machine with no `xattr` incantation
- [ ] A signed Windows binary shows no SmartScreen block from a verified publisher
- [ ] Every artifact carries a Sigstore signature, signed or not
- [ ] With signing disabled, the release notes still carry the current blunt warning
- [ ] Signing secrets live in a protected environment with required reviewers
- [ ] `docs/RELEASING.md` records the yearly costs, the renewal dates and the rotation steps

**Scope** L

---

## 08 — docs(deploy): a route onto a managed laptop, and a working disclosure path

**Goal** Give a school IT administrator the one page they need, and give a
security researcher somewhere to send a bypass.

**Why it matters** `SAFETY.md` says "See SECURITY.md" and there is no
`SECURITY.md`. A triage tool with no disclosure channel invites a public issue
describing a bypass, which is the worst outcome for its users. Separately, the
adoption blocker is not "can this be downloaded" but "will the SOE let it run",
and the answer — allowlist it by the SHA-256 the release already publishes — is
not written down anywhere.

**Files**
- `SECURITY.md` — new
- `docs/DEPLOYING.md` — new
- `scripts/windows_add_context_menu.reg` — fix
- `CONTRIBUTING.md` — remove the stale instructions
- `requirements-dev.txt` — reconcile with the `[dev]` extra

**Implementation** `SECURITY.md`: private GitHub Security Advisories as the
channel, a stated response window, and an explicit scope — a detection **bypass**
(a file that should be flagged and is not, a way to make the report misrepresent
a file, a way to make a detector write to disk or execute anything) is in scope;
"it did not detect this novel malware sample" is not, because the README already
says a novel technique will come back clean. `docs/DEPLOYING.md`: the three
routes in order of how locked-down the machine is — pip for a machine with
Python, the signed binary, and hash-allowlisting for AppLocker or WDAC where the
published `.sha256` is the exact input the policy needs. The `.reg` file is
currently broken twice over: it invokes `TeacherSafeScanner.exe`, a name the build
has never produced, and it passes `"%1"` with no subcommand, so argparse's
required subparser rejects it with exit code 4 and the console window closes
before anyone reads why. Rewrite it to call `teacher-safe-scan.exe scan "%1"`
under `cmd /k` so the output stays visible, add a `Directory\shell` entry since
the unit of work is a folder, and use `REG_EXPAND_SZ` if `%ProgramFiles%` is
meant to expand. `CONTRIBUTING.md` still points at `requirements-optional.txt`,
deleted in the revival, and at `pip install -r requirements.txt`, which now
installs nothing because that file is a comment block; replace with
`pip install -e ".[dev]"` and the actual check commands from CI.
`requirements-dev.txt` lists `pyinstaller` while the `[dev]` extra does not — pick
one source of truth and make the other a pointer.

**Tests** A docs link check in CI that fails on a relative Markdown link to a
file that does not exist. That single check would have caught the missing
`SECURITY.md`.

**Depends on:** nothing

**Risk** None to the code. The `.reg` change should be verified on a real Windows
machine; a registry file that half-works is worse than none.

**Acceptance criteria**
- [ ] `SECURITY.md` exists, is linked from `SAFETY.md` and `README.md`, and states scope
- [ ] CI fails on any broken relative link in the Markdown
- [ ] The context-menu entry actually scans and leaves its output on screen
- [ ] `CONTRIBUTING.md`'s commands all work on a fresh clone
- [ ] `docs/DEPLOYING.md` covers pip, signed binary and hash-allowlisting

**Scope** S

---

## 09 — refactor(core): scan from an open handle, not only from a path

**Goal** Split `scan_file` into a filesystem front half and a
`scan_stream(handle, …)` back half, so anything that can produce bytes can be
triaged.

**Why it matters** Everything downstream needs it. An LMS export is one ZIP
containing thirty submissions; the product answer is thirty rows, and the
project's invariant is that no archive is ever extracted to a filesystem path.
Those two facts can only both hold if a submission can be scanned from an
in-memory handle. Rule packs need it too, because `_run_yara` currently matches
on a file path that a member inside an archive does not have.

**Files**
- `scanner/scanner_core.py` — `scan_file`, new `scan_stream`, `_dispatch`, `ScanResult`
- `scanner/triage.py` — `build_summary` handles results with a container
- `tests/test_scanner_core.py` — stream-path coverage

**Implementation** `scan_file` keeps what needs a filesystem: `analyze_name`, the
symlink branch, `stat`, the empty-file and size gates. Everything after the
`path.open("rb")` — `sha256_of`, `read_head`/`sniff_magic`, `analyze_content`,
`_dispatch`, `_dedupe`, `decide` — moves into
`scan_stream(handle, *, name, size, config, container=None)`. `_dispatch` takes
`path.suffix` and `path.name` only, so widen its parameter to `PurePath` and let
callers pass a `PurePosixPath` built from a member name. Add
`ScanResult.container: Optional[str]` recording which archive a result came from,
carried through `to_dict`/`from_dict`; leave submitter attribution to 11 so the
JSON schema changes once per concept rather than twice. `_run_yara` still takes a
path: for a stream result with no path, make it emit the existing
`inspection_incomplete` non-result rather than crash — commit 13 removes the
special case entirely.

**Tests** `scan_stream` over an `io.BytesIO` of each corpus sample produces the
same findings and verdict as `scan_file` over the same bytes on disk — a
parametrised equivalence test across the whole `SAMPLES` table is the strongest
form of this and is cheap. Existing `test_scanner_core.py` tests must pass
untouched, which is the point of the split.

**Depends on:** nothing

**Risk** Moderate: this is the hot path and every detector runs through it. The
equivalence test over the whole corpus is what makes it safe. Watch for handle
position assumptions — several detectors `seek(0)` themselves
(`analyze_office`, `analyze_archive`, `read_head`) but `_appended_data` and
`_trailing_bytes` rely on `size` being passed correctly, which is now the
caller's job rather than a `stat` result.

**Acceptance criteria**
- [ ] `scan_stream` and `scan_file` produce identical results for every corpus sample
- [ ] `scan_file` is a thin wrapper: filesystem gates, then delegate
- [ ] `ScanResult.container` round-trips through JSON
- [ ] No detector signature changes
- [ ] `scripts/check_corpus.py` passes unchanged

**Scope** M

---

## 10 — feat(ingest): read LMS bulk-export archives without extracting them

**Goal** `teacher-safe-scan scan submissions.zip` produces one row per student
submission, not one row for the ZIP.

**Why it matters** This is the wedge. The workflow that actually happens is: open
the LMS, click "Download all submissions", get a ZIP, and then have no idea what
is in it. Today that ZIP gets a single row saying it contains other archives.
Every existing competitor is worse at this, not better — Dangerzone cannot take a
folder at all, and oletools has no notion of a batch. Duplicate detection by
SHA-256 in `build_summary` also becomes genuinely useful here: two byte-identical
submissions from different students is a signal a teacher wants.

**Files**
- `scanner/ingest.py` — new
- `scanner/scanner_core.py` — dispatch an export to the ingest walker
- `scanner/limits.py` — `max_member_scan_bytes`
- `SAFETY.md` — a row in the limits table
- `tests/test_ingest.py` — new

**Implementation** `detect_layout(names) -> ExportLayout | None` votes over member
names and returns a layout with a confidence. The four shapes worth supporting:
**Canvas** — flat, `lastnamefirstname_<userid>_<submissionid>_<original>.ext`,
with `_late_` inserted for late work, group submissions using the group name, and
resubmissions suffixed `-1`, `-2` before the extension. **Moodle** — one directory
per submission, `Firstname Lastname_<id>_assignsubmission_file_/<original>`, with
an `_assignsubmission_onlinetext_` variant. **Blackboard** — 
`<Assignment>_<username>_attempt_<timestamp>_<original>` plus a per-submission
`.txt` receipt that should be recognised and not reported as a submission.
**Google Classroom via Drive** — flat, `Student Name - Original Name.ext`. When no
layout wins, fall back to treating the archive as a plain archive, which is
today's behaviour. Members are read through `zipfile.ZipFile.open` into a bounded
`io.BytesIO` and handed to `scan_stream`; nothing is written to disk, and
`tests/test_detectors_archive.py::test_nothing_is_written_to_disk` gains a sibling
for this path. The existing `analyze_archive` checks still run on the container
first — an LMS export is still an archive and traversal or bomb findings on the
container matter more than any member. Add `max_member_scan_bytes` (32 MB)
rather than reusing `max_nested_extract_bytes` (16 MB), because a legitimate
video submission is larger than a legitimate nested archive; anything over it is
reported incomplete.

**Never guess an attribution.** A layout match below the confidence threshold
yields an unattributed row, not a guessed student name. A wrong name on a report
that may be forwarded to a parent is far worse than a missing one.

**Tests** A fixture builder per layout producing a synthetic export from the
existing corpus builders — a Canvas ZIP containing `office_with_macro.docm` under
a mangled Canvas name, and so on. Assert the member is flagged, the original
filename is recovered, and the row count equals the submission count. Assert a
plain `.zip` of coursework is still handled as a plain archive. Assert a
Blackboard receipt `.txt` is not counted as a submission. Assert a member over
`max_member_scan_bytes` becomes `COULD NOT FULLY INSPECT`.

**Depends on:** 09

**Risk** The filename grammars are the fragile part — they vary by LMS version and
by institution configuration, and there is no specification for any of them.
Mitigate by keeping detection conservative, printing which layout was detected,
and making `--lms none` an escape hatch (commit 11). Second risk: a hostile export
whose member names are crafted to look like a different layout — attribution is
display metadata only and must never influence a verdict, which the design
already guarantees because attribution happens after `decide()`.

**Acceptance criteria**
- [ ] Canvas, Moodle, Blackboard and Classroom-via-Drive exports each yield one row per submission
- [ ] Original filenames are recovered and shown alongside the mangled member name
- [ ] Nothing is written to disk during ingest, with a test asserting it
- [ ] A plain coursework `.zip` is unaffected
- [ ] Low-confidence layout matches produce unattributed rows, never guessed names
- [ ] `SAFETY.md`'s limits table lists `max_member_scan_bytes`

**Scope** L

---

## 11 — feat(cli): submitter attribution through triage and exit codes

**Goal** Carry the student name from ingest to the console table, the summary and
the JSON report, and decide what quarantine means for a file that lives inside an
archive.

**Why it matters** "Three of thirty submissions" is the product's sentence.
Making it "three students" is the difference between a list of filenames and an
answer a teacher can act on in the ten minutes before a lesson.

**Files**
- `scanner/scanner_core.py` — `ScanResult.submitter`
- `scanner/triage.py` — `TriageSummary.by_submitter`, `headline()`
- `scanner/main.py` — `--lms`, `_quarantine_results`, console output
- `scanner/reporters.py` — `print_console_report` gains a submitter column when populated

**Implementation** Add `submitter: Optional[str]` to `ScanResult` and round-trip
it. `build_summary` gains a `by_submitter` mapping and an `unattributed` count.
`headline()` grows an export-shaped variant — "4 of 29 submissions should not be
opened, from 3 students" — while leaving the existing folder wording untouched;
both are tested. The CLI gets
`--lms {auto,canvas,moodle,blackboard,classroom,none}`, defaulting to `auto`, and
prints one line naming the detected layout and submission count before the table.
Auto-detection that happens silently is wrong in a security tool: the operator
must be able to see that the tool decided something.

Quarantine needs an explicit decision. A member inside an export has no
filesystem path, so `_quarantine_results` calling `store.quarantine(result.path)`
would fail per member. Quarantine the **container** once, with a reason listing
the member codes that triggered it, and print exactly that. Silently skipping
would be the worst option: the teacher would believe flagged files were moved
aside when they were not.

**Tests** Console output for an export includes a submitter column and omits it
for a plain folder. Exit codes are unchanged by attribution. JSON round-trips
`submitter` and `container`. Quarantining an export moves the export once, not
zero times and not once per member, and says so.

**Depends on:** 10

**Risk** Low, mostly presentation. The quarantine semantics are the judgement
call and should be stated in the README next to the existing "nothing is ever
deleted" guarantees.

**Acceptance criteria**
- [ ] The console table shows a submitter column when attribution exists, and no empty column when it does not
- [ ] The headline counts students as well as files for an export
- [ ] `--lms none` reverts to plain-archive behaviour
- [ ] The detected layout is printed, never applied silently
- [ ] Quarantining an export moves the container once and reports which members caused it
- [ ] `submitter` and `container` survive a JSON round-trip

**Scope** M

---

## 12 — feat(report): group by student, and write the message to that student

**Goal** Make the HTML report and the window answer "which students do I need to
talk to", and produce the paragraph a teacher sends to one of them.

**Why it matters** `summarise_for_email` already produces a block for IT. The
other message a teacher has to write is to the student: "the file you submitted
could not be opened safely, please re-send it as X". Writing that thirty times is
the work the tool should remove.

**Files**
- `scanner/reporters.py` — `generate_html_report`, `_result_html`
- `scanner/gui_model.py` — `message_for_submitter`, a `submitter` field on `RowView`
- `scanner/gui.py` — a Student column and a "Copy message for this student" button
- `tests/test_reporting_and_cli.py` — coverage for both

**Implementation** The HTML report gains a "By student" section, worst student
first, above the existing per-verdict groups; a batch with no attribution renders
exactly as it does today. `_result_html`'s summary line shows the recovered
original filename as the label and the mangled member name as secondary metadata
— the Canvas member name is unreadable and should not be what a teacher scans
down a column. `message_for_submitter(summary, submitter)` produces a short plain
block covering only that student's files, with the finding's `action` text as the
instruction, and it must not name any other student.

**A student name from an LMS filename is attacker-controlled input.** Every
submitter string goes through `sanitize_display` before it reaches HTML, the
console or a Tk widget, exactly as filenames already do — otherwise a student who
renames their submission with a bidi override reorders the report that is about
them. There is already a test for this shape
(`test_bidi_names_cannot_spoof_themselves_in_the_report`); extend it to
submitters.

**Tests** Report with attribution contains a By-student section and every
submitter appears sanitised. Report without attribution is byte-identical to the
current output for the same summary. `message_for_submitter` mentions only that
student's files. The GUI's Student column is hidden for a plain folder scan.

**Depends on:** 11, 02

**Risk** Low. Keep the no-JavaScript, no-network guarantee — the existing
`test_html_report_is_self_contained` test enforces it and must not be relaxed for
a collapsible By-student section; `<details>` is already how the report does
disclosure without script.

**Acceptance criteria**
- [ ] The report groups by student, worst first, when attribution exists
- [ ] A folder scan's report is unchanged
- [ ] Submitter names are sanitised everywhere they are rendered
- [ ] `message_for_submitter` names one student's files and no others
- [ ] The report still contains no script and makes no network request

**Scope** M

---

## 13 — feat(rules): rule packs a school can add without touching the code

**Goal** Let a school ship its own detections — as YARA rules where
`yara-python` is available, and as a stdlib-only literal-match pack where it is
not.

**Why it matters** Every school has a local pattern: the phishing template that
circulates each September, a filename their SIS produces, a macro their own
finance office uses legitimately. Today the only extension point is
`--yara-rules <one file>`, which requires a compiler-backed dependency that will
not install on a locked-down machine, and which produces findings with no
teacher-facing text unless the rule author happened to write `meta:` fields.

**Files**
- `scanner/rules.py` — new: `RulePack.load`, `RulePack.match`
- `scanner/scanner_core.py` — replace `_run_yara`, compile once per scan
- `scanner/main.py` — `--rules-dir`, `--yara-rules` kept as an alias
- `examples/rule_packs/example/` — a demonstrable pack
- `scripts/check_corpus.py` — `--rules-dir` mode
- `SAFETY.md` — what a rule pack can and cannot do

**Implementation** A pack is a directory: `*.yar`/`*.yara` files plus a
`pack.json` manifest. JSON, not TOML, because `requires-python = ">=3.10"` and
`tomllib` arrives in 3.11. The manifest supplies the five human fields
(`plain`, `why`, `action`, `severity`, `confidence`) per rule name, so a rule
author can use stock YARA rules without editing them; YARA `meta:` values still
work and take precedence, as `_run_yara` already implements. **A rule missing
`plain`, `why` or `action` fails to load, loudly.** That is the same bar
`docs/ARCHITECTURE.md` sets for built-in detectors, and a finding a teacher
cannot read is worse than no finding.

Two real defects get fixed here. `_run_yara` calls `yara.compile` **inside the
per-file path**, so scanning thirty files compiles the rules thirty times. Compile
once when `ScanConfig` is built. And it calls `rules.match(str(path))`, which
cannot work for a member scanned from a stream; switch to `rules.match(data=…)`
over bounded bytes, which is why this depends on 09. Also, a missing rules file
currently produces a `yara_no_rules` finding on *every* file — thirty identical
rows in the report; make a load failure one message on stderr and one batch-level
note.

The stdlib fallback keeps `pack.json` entries with `literal` (ASCII or hex byte
strings, minimum four bytes) and `filename_glob`, matched against the same
bounded head/tail windows the detectors already use. Deliberately weak: no regex,
so no catastrophic backtracking on attacker-controlled input, and no code
execution of any kind. Say that in `SAFETY.md` — a rule pack is data, and a
plugin system that executed code would undo the guarantee the whole project rests
on.

**Tests** Loading a pack with a rule missing `why` fails with a message naming the
rule. Rules compile once per scan, asserted by counting calls. A literal-match
pack fires on the corpus's known harmless payload string. A pack directory that
does not exist is one error, not one finding per file. Matching works for a
member scanned from a stream. `scripts/check_corpus.py --rules-dir
examples/rule_packs/example` passes.

**Depends on:** 09

**Risk** Moderate. Rule severity is under the school's control, and a pack that
declares everything `high`/`high` will flood the DO NOT OPEN column under rule 2.
Cap what a pack may declare — `high`/`high` is allowed but the loader warns, and
`docs/SCORING.md` gains a paragraph explaining that a pack cannot change the four
rules, only add findings that feed them.

**Acceptance criteria**
- [ ] `--rules-dir` loads a directory of YARA rules plus a `pack.json`
- [ ] Rules compile once per scan, not once per file
- [ ] Matching works on bytes, so members inside an LMS export are covered
- [ ] A rule without teacher-facing text refuses to load
- [ ] A stdlib-only pack works with `yara-python` absent
- [ ] `scripts/check_corpus.py --rules-dir` gates a school's own pack the way CI gates ours
- [ ] `SAFETY.md` states that packs are data and cannot execute anything

**Scope** L

---

## 14 — feat(detectors): RTF

**Goal** Give `.rtf` submissions the same treatment `.docx` gets.

**Why it matters** Verified: an RTF containing `\objdata` produces zero findings
and lands in `LIKELY SAFE TO REVIEW`. `sniff_magic` already recognises `{\rtf`
and `EXTENSION_EXPECTATIONS` maps `.rtf → {rtf}`, so the extension check passes
and `_dispatch` has no RTF branch — the file falls through everything. RTF is a
long-running carrier for embedded OLE and Equation Editor exploits precisely
because it is treated as a plain-text-ish format by tools that inspect `.docx`
carefully.

**Files**
- `scanner/detectors/rtf.py` — new
- `scanner/detectors/__init__.py` — export `analyze_rtf`
- `scanner/scanner_core.py` — an RTF branch in `_dispatch`
- `scanner/corpus.py` — `rtf_embedded_object.rtf`, `clean_notes.rtf`
- `scripts/check_corpus.py` — two rows
- `README.md` — RTF in the Office section

**Implementation** `analyze_rtf(handle, *, limits)` streams with the existing
`iter_windows`, with the overlap derived from the longest token exactly as
`pdf.py` does — that bug is documented in `pdf.py`'s docstring and must not be
reintroduced. Check for `\objdata` and `\objupdate` (an embedded object that
refreshes on open, `HIGH`/`MEDIUM`), `\objclass` naming an executable-ish class,
the `Equation.3` / `Equation Native` strings in the hex payload (reuse the
reasoning already written for `office_equation_object`, `MEDIUM`/`LOW`, since
maths coursework legitimately contains equations), `\dde` and `\ddeauto`
(`HIGH`/`MEDIUM`, matching `office_dde_field`), and an RTF whose `{\rtf` header is
not at byte 0 (`MEDIUM`, matching `pdf_header_offset`). Decode nothing and parse
nothing: scan bytes and report structure, like every other detector here. Note
that whitespace and comment groups can be interleaved inside a control word to
evade a naive literal search — normalise only by stripping whitespace within a
bounded window, and where a match is only reached after normalisation, report it
at lower confidence and say so in the evidence.

**Tests** A clean RTF produces no findings — that assertion matters more than the
positive ones. `\objdata` fires. An obfuscated `\ob jdata` fires at lower
confidence. A `.rtf` whose contents are actually a PE is caught by the existing
`content_is_executable` path and not double-reported.

**Depends on:** nothing

**Risk** RTF's grammar is permissive and false positives are the failure mode
that gets the tool uninstalled. Keep confidence honest and make sure the clean
sample stays clean in `check_corpus.py`, which asserts both directions.

**Acceptance criteria**
- [ ] An RTF with `\objdata` is `DO NOT OPEN` or `REVIEW WITH CAUTION`, never safe
- [ ] A clean RTF produces zero findings
- [ ] Detection streams, with overlap derived from the longest token
- [ ] Two corpus samples, one clean, one flagged
- [ ] README lists RTF among the document formats checked

**Scope** M

---

## 15 — feat(detectors): HTML, SVG and script-bearing markup

**Goal** Check the submissions that are web pages, including the ones with a
`.svg` extension.

**Why it matters** Verified: an `.svg` containing `<script>` gets no checks at
all, because `.svg` is in neither `IMAGE_SUFFIXES` nor `TEXTISH_SUFFIXES` and has
no magic signature. An `.html` file gets `analyze_text_urls` and nothing else, so
HTML smuggling — a page whose body is a base64 blob reassembled into a download
by script — passes clean. Both formats arrive routinely in real submissions.

**Files**
- `scanner/detectors/markup.py` — new
- `scanner/detectors/base.py` — an SVG case in `sniff_magic`
- `scanner/scanner_core.py` — `.svg`, `.xhtml`, `.mht`, `.mhtml` in dispatch
- `scanner/corpus.py` — three samples
- `scripts/check_corpus.py` — three rows

**Implementation** Check for `<script>` blocks, `javascript:` and
`data:text/html` in `href`/`src`, `<iframe>` with an external source, inline
`onload=`/`onerror=` handlers, `<meta http-equiv="refresh">`, `<foreignObject>` in
SVG, and a body that is dominated by one long base64 run. Byte scan only; do not
parse HTML, and specifically do not reach for `html.parser` on hostile input for
the same reason `office.py` refuses stdlib ElementTree.

**The false-positive trap is the whole difficulty.** A web-design assignment is
*supposed* to contain a script, and flagging every one of them makes the tool
useless in a computing department. So: a script in an `.html` file is `LOW`
severity with text that says exactly that — "this is a web page that runs code,
which is normal for a web-design assignment and unusual for an essay". A script
inside an `.svg` is `MEDIUM`, because an SVG that a student exported from a
drawing tool has no reason to contain one. HTML smuggling shape — a script plus a
multi-kilobyte base64 blob plus a synthesised download — is `HIGH`/`MEDIUM`. The
corpus must include `clean_webpage.html`, a genuine scripted web-design
submission, expected no worse than `REVIEW WITH CAUTION`; that row is the one
that keeps this detector honest.

**Tests** Clean scripted web page stays at caution or below. `svg_with_script.svg`
is flagged. `html_smuggling.html` is `DO NOT OPEN`. An `.svg` sniffs as `svg`
rather than `unknown`. No regression in `analyze_text_urls` for `.html`, which
still runs.

**Depends on:** nothing

**Risk** Higher false-positive risk than any other detector here. If the clean
scripted page cannot be kept below `DO NOT OPEN`, ship only the SVG and smuggling
checks and leave plain HTML to the URL detector.

**Acceptance criteria**
- [ ] `.svg` is dispatched and sniffed correctly
- [ ] A scripted web-design submission does not reach `DO NOT OPEN`
- [ ] HTML smuggling shape is caught
- [ ] No HTML or XML parser touches untrusted bytes
- [ ] Three corpus rows, one of them the clean scripted page

**Scope** M

---

## 16 — feat(cli): make `--*-rules strict` mean something

**Goal** Either implement the strict tier the CLI advertises, or remove it.

**Why it matters** `build_parser` offers `--pdf-rules`, `--office-rules`,
`--zip-rules` and `--image-rules` with `choices=("off","normal","strict")`, and
`_dispatch` only ever tests `!= "off"`. `strict` is accepted and does nothing. A
security tool that advertises a sensitivity setting it does not have is lying to
its operator, and someone will make a decision based on it.

**Files**
- `scanner/scanner_core.py` — thread `mode` into each detector call
- `scanner/detectors/pdf.py`, `office.py`, `archive.py`, `image.py` — a strict tier each
- `scanner/main.py` — help text saying what strict actually changes
- `docs/SCORING.md` — a section defining it

**Implementation** Pass the family's mode into each `analyze_*` as a keyword and
define the tier concretely, one family at a time. PDF strict: report object
streams — `OBJSTM_RE` is compiled in `pdf.py` and never referenced, which is where
this was clearly heading — and promote `pdf_submit_form` from `LOW`/`LOW` to
`MEDIUM`. Office strict: report every external relationship type including
`hyperlink`, which `_external_relationships` currently skips outright, and report
`printerSettings` parts, for which `PRINTER_SETTINGS_RE` is likewise compiled and
never used. Archive strict: lower `max_compression_ratio`, and report any nested
archive rather than only at depth 0. Image strict: promote
`image_small_trailer` from `INFO` to `LOW`.

If any of those tiers cannot be justified, delete that family's `strict` choice
rather than leaving it inert. Removing a flag that never worked is a smaller lie
than keeping it.

**Tests** For each family, a sample that is clean at `normal` and flagged at
`strict`, and a sample that is flagged at both. A test asserting no `strict`
choice remains that does not change behaviour — parametrised over the four
families, this is the check that keeps the flag honest.

**Depends on:** nothing (land after 14 and 15 if those are done, so their findings
get a strict tier from the start rather than an inconsistent one later)

**Risk** Low. Strict is opt-in and off by default, so the only cost of getting a
tier wrong is a noisier scan for someone who asked for one.

**Acceptance criteria**
- [ ] Every surviving `strict` choice changes behaviour, with a test proving it
- [ ] `OBJSTM_RE` and `PRINTER_SETTINGS_RE` are used or deleted
- [ ] `docs/SCORING.md` defines strict per family
- [ ] Help text says what strict changes, not just that it exists
- [ ] Default behaviour is byte-identical to before

**Scope** M

---

## 17 — fix(limits): stop reporting every large PDF as unchecked, and bound wall-clock

**Goal** Fix a false positive that will hit a teacher's first real batch, and add
the one resource ceiling `ScanLimits` is missing.

**Why it matters** Verified: a structurally clean 12.1 MB PDF is reported
`COULD NOT FULLY INSPECT` with a single `pdf_truncated_scan` finding. Scanned
worksheets, slide exports and anything with photographs routinely exceed 8 MB, so
a real folder of submissions produces a column of blue "NOT CHECKED" rows for
files that are fine. `docs/SCORING.md` argues that a triage tool which cries wolf
gets uninstalled; this is that failure, in the format teachers receive most.

The cause is a conflation in `ScanLimits`. `max_read_bytes` is documented as
"largest slice any detector may hold in memory at once" — 8 MB — but
`iter_windows` uses it to bound *total bytes ever streamed*, while holding only
one 512 KB window. The PDF detector never holds more than a window, so the 8 MB
ceiling is enforcing a constraint the code does not have.

Separately, there is no wall-clock bound anywhere. `SAFETY.md` says resource
limits are part of the threat model and lists eight of them; time is not among
them, so a pathological file can occupy a worker thread indefinitely inside a
bounded-byte loop.

**Files**
- `scanner/limits.py` — `max_stream_bytes`, `max_seconds_per_file`; clarify `max_read_bytes`
- `scanner/detectors/base.py` — `iter_windows` bounds by the streaming limit and honours a deadline
- `scanner/scanner_core.py` — set the deadline in `scan_file`/`scan_stream`
- `scanner/corpus.py` + `examples/.gitignore` — a large clean PDF, generated not committed
- `SAFETY.md`, `docs/SCORING.md` — the table and the worked examples

**Implementation** Split the two concepts: `max_read_bytes` keeps its documented
meaning as the largest single in-memory slice (used by `_analyze_legacy_ole`,
which really does hold 4 MB), and a new `max_stream_bytes` (64 MB) bounds what a
streaming detector may read in total. `iter_windows` uses the latter. Add
`max_seconds_per_file` (30 s), set as a deadline when a file starts and checked
between detectors and once per window inside `iter_windows`; on expiry emit an
`inspection_incomplete` finding naming the elapsed time, which is the honest
outcome and lands the file in `COULD NOT FULLY INSPECT` where it belongs.

The corpus needs a large clean PDF to pin this, and a 12 MB file must not enter
git. `check_corpus.py` already calls `write_samples` into a `TemporaryDirectory`,
so add the sample to `SAMPLES` and add its name to `examples/.gitignore` so the
committed `examples/benign_samples/` copy stays small.

**Tests** A 12 MB structurally clean PDF is `LIKELY SAFE`. A 12 MB PDF with
`/Launch` past the 8 MB mark is still `DO NOT OPEN` — the point of raising the
bound. A file past `max_stream_bytes` is still reported incomplete. A detector
that exceeds the deadline yields an incomplete finding rather than hanging, using
a monkeypatched slow detector.

**Depends on:** nothing

**Risk** Raising a limit raises worst-case scan time for large batches. 64 MB
streamed at window size with no allocation growth is cheap, but measure it on the
corpus and record the number. The deadline check must not itself become a
per-window `time.perf_counter()` cost in the hot loop — check every N windows.

**Acceptance criteria**
- [ ] A clean 12 MB PDF is `LIKELY SAFE TO REVIEW`
- [ ] A finding past 8 MB in a large PDF is still detected
- [ ] `ScanLimits` distinguishes single-slice from total-streamed, with the docstrings to match
- [ ] A file that exceeds `max_seconds_per_file` becomes `COULD NOT FULLY INSPECT`
- [ ] `SAFETY.md`'s limits table lists all of them, including time
- [ ] The large sample is generated, not committed

**Scope** M

---

## 18 — docs(readme): the screenshot the README asks for, and a refreshed sample report

**Goal** Remove the placeholder instruction block from the front page and put the
picture there instead.

**Why it matters** The README currently ships a blockquote telling the reader to
generate `demo.html` themselves and drop an image at `docs/report.png`. That is a
note-to-self on the shop window of a project whose main proof surface is the
report. `.gitignore` still excludes `/docs/demo.gif` and
`/docs/demo-placeholder.gif` from a previous life of this repository. And
`examples/sample_report.json` records "15 of 29 files should not be opened",
which commits 03, 14 and 15 will have made wrong.

**Files**
- `docs/report.png`, `docs/window.png` — new
- `README.md` — replace the instruction block; refresh the ASCII table if counts moved
- `examples/sample_report.json` — regenerate
- `scripts/make_screenshots.py` — new
- `.gitignore` — drop the dead demo-gif entries

**Implementation** `scripts/make_screenshots.py` regenerates `demo.html` and
`examples/sample_report.json` from the committed corpus with `generated_at` and
`duration_ms` pinned, so re-running it does not produce a diff on every
invocation, and prints the two capture commands. Capture stays manual — gating CI
on a headless browser for a screenshot is not worth the dependency, and the
script guarantees the underlying data is reproducible even if the pixels are not.
Take `docs/window.png` from the Tk window, which by this point has actually run.
Refresh the ASCII table in the README from the real output rather than by hand;
the counts in it must match what `python -m scanner scan examples/benign_samples`
prints, since the README explicitly claims anyone can reproduce it exactly.

**Tests** A test asserting the committed `examples/sample_report.json` matches a
freshly generated one, ignoring the pinned timestamp fields. That converts a
stale sample report from something nobody notices into a CI failure.

**Depends on:** 02, 03, 14, 15

**Risk** None. Keep the images small; a README that takes a second to load on a
school network is a bad first impression for a tool whose pitch is that it works
on a school network.

**Acceptance criteria**
- [ ] `README.md` shows the report and the window, with no instruction block
- [ ] The ASCII table matches real output for the committed corpus
- [ ] `examples/sample_report.json` matches the current detectors, enforced by a test
- [ ] `scripts/make_screenshots.py` regenerates the inputs deterministically
- [ ] `.gitignore` has no entries for files that no longer exist

**Scope** S

---

## What is deliberately not here

**No hosted mode, no upload path, not even a hash lookup.** A VirusTotal query
would improve detection immediately and is the single most tempting addition on
this list. It is also the one that ends the project. The README's privacy section
— "there is no telemetry, no update check, no network code of any kind in the
scanner" — is what makes this installable in a school without a data-protection
review, and student work is student data. A SHA-256 sent to a third party is a
disclosure that the file existed and, for any file that service has already seen,
what it contains. The moment there is network code in `scanner/`, that paragraph
becomes false and the tool becomes a procurement problem instead of a download.

**No machine-learning classifier.** A model would score better on a benchmark and
would be unable to do the one thing `docs/SCORING.md` requires: explain a verdict
in a sentence a teacher can forward to a parent, and let a school IT reviewer
disagree with the specific rule rather than with a number. The four rules in
`scanner/verdict.py` are about sixty lines, and that is a feature. Detection
improvements belong in detectors that can state their evidence.

**No sanitisation, no "produce a safe copy".** This is Dangerzone's problem and
Dangerzone solves it properly, with containers and a rebuilt PDF. Doing it here
would mean rendering or converting attacker-controlled input, which breaks the
first invariant in `docs/ARCHITECTURE.md` and in `SAFETY.md` — nothing is
executed. The two tools compose: triage here, sanitise there. Building a worse
version of the other half is how a focused tool becomes a mediocre suite.

**No configuration file for verdict thresholds.** `docs/SCORING.md` says the
rules live in `scanner/verdict.py`, about sixty lines, no configuration file,
deliberately — because a threshold a school can quietly lower is a threshold that
gets lowered until the tool stops reporting anything, and because a verdict that
depends on unseen local configuration cannot be reasoned about from a report
alone. Commit 13 is the sanctioned extension point: a school can add findings,
and those findings feed the same four rules everyone else's do. Adding a finding
is auditable in the pack; changing the rules is not.
