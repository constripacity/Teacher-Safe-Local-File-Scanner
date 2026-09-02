# Architecture

```
scanner/
├─ findings.py      Finding, Severity, Confidence, Verdict — the vocabulary
├─ limits.py        ScanLimits — every ceiling the scanner obeys, in one struct
├─ verdict.py       The four rules that turn findings into a verdict
├─ scanner_core.py  Walk targets, open each file once, dispatch, decide
├─ triage.py        Folder-level summary: counts, duplicates, headline
├─ reporters.py     Console / JSON / self-contained HTML
├─ quarantine.py    Move-only store with an append-only manifest and restore
├─ gui_model.py     Everything the window shows — no Tk import, fully tested
├─ gui.py           Tkinter widgets and wiring only
├─ main.py          CLI
└─ detectors/
   ├─ base.py       Bounded reads, magic sniffing, filename analysis primitives
   ├─ archive.py    ZIP family: traversal, bombs, encryption, bounded recursion
   ├─ office.py     OOXML + legacy OLE
   ├─ pdf.py        Bounded streaming structural scan
   ├─ image.py      PNG/JPEG/GIF container structure and polyglots
   └─ general.py    Filename and content checks that apply to any file
```

## Two invariants

Every detector must hold both. They are the reason this tool is safe to run on
hostile input.

**1. Nothing is executed.** No macro runs, no PDF is rendered, no archive is
extracted to a path the operating system could act on, no image is decoded.
Detectors read bytes and report structure.

**2. Nothing is unbounded.** Reads, recursion depth, archive member counts and
finding counts are all capped by `ScanLimits`. Detectors receive an open handle
and stream; none calls `f.read()` without a bound.

`tests/test_detectors_archive.py::test_nothing_is_written_to_disk` is a
regression guard for the first. `ScanLimits` is a single frozen dataclass so a
reviewer can read one struct and know exactly what the scanner refuses to do.

## Data flow

```
path
 └─ scan_file()
     ├─ analyze_name()               filename-only checks
     ├─ stat / symlink / size gates  → COULD_NOT_INSPECT on any failure
     ├─ open once → sha256, magic sniff
     ├─ _dispatch()                  by sniffed type first, extension second
     │    ├─ office / archive / pdf / image / text detectors
     │    └─ optional YARA
     ├─ _dedupe()                    (code, evidence) pairs
     └─ decide()                     the four rules → Verdict + risk_score
```

Dispatch is by **content, then name**. A Windows executable renamed
`holiday_photo.png` is analysed as an executable, because that is what the
operating system will do with it.

## Adding a detector

1. Write a module in `scanner/detectors/` exposing
   `analyze_x(handle, *, limits, ...) -> list[Finding]`.
2. Every `Finding` needs all five human fields: `plain`, `why`, `action`,
   `evidence`, plus `severity` and `confidence`. If you cannot write the `why` in
   one sentence a non-technical reader understands, the detector is not ready.
3. Set `inspection_incomplete=True` for anything meaning "I could not finish
   looking". That is what keeps unchecked files out of the green column.
4. Wire it into `scanner_core._dispatch`.
5. Add a **benign** sample to `examples/generate_benign_samples.py` and a row to
   `scripts/check_corpus.py`. Never commit real malware; reproduce the
   *structure* with an inert payload.
6. Add tests in `tests/test_detectors_*.py`, including at least one asserting a
   normal file does **not** trigger it. False positives are the failure mode
   that gets this tool uninstalled.

## Why the GUI is split in two

`gui_model.py` has no `import tkinter`. Every decision about what the window
shows — row ordering, colours, detail text, the paste-into-email summary — lives
there and is unit tested on a machine with no display. `gui.py` is widgets and
wiring, and is exercised by hand. This split exists because the development and
CI environments for this project frequently have no `tkinter` at all.

## Threading

`scan()` uses a `ThreadPoolExecutor`; the work is I/O-bound so the GIL is not the
constraint. Each `scan_file` call opens its own handle and shares nothing
mutable. The GUI runs the scan on a worker thread and marshals progress back
through a `queue.Queue` drained on the Tk main loop — Tk widgets are only ever
touched from the main thread.
