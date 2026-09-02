# How a verdict is decided

This document exists so that a school IT reviewer can disagree with this tool
*specifically*, rather than with an unexplained number.

## Why the old model was replaced

Version 0.2 summed integers from a table:

```python
WEIGHTS = {"exe_in_zip": 40, "pdf_token": 20, "office_macro_container": 45, ...}
score = min(sum(WEIGHTS.get(code, 5) for code in findings), 100)
```

Four problems made it indefensible:

1. **The numbers had no origin.** Why is a macro 45 and a PDF token 20? Nothing
   said, and nothing could be argued with.
2. **Repetition inflated the result.** An archive containing 900 `.exe` files
   saturated at 100 exactly like an archive containing one. The score carried no
   more information than a boolean.
3. **Certainty and severity were conflated.** "This file definitely contains a
   macro" and "this file might have data appended after the image" both became
   "+n points".
4. **A file that could not be checked scored 0 and was labelled `Safe`.**
   Oversized files, unreadable files and errored files all came back green. For
   a triage tool, that is the most dangerous possible default.

## The model now

### Two independent axes

**Severity** — how bad this would be *if the finding is correct*:

| | Meaning |
| --- | --- |
| `info` | Worth stating, implies no risk (a hidden `.DS_Store`, an empty file) |
| `low` | A weak signal that is frequently benign (a shortened link, a nested archive) |
| `medium` | Meaningful, with known benign causes (an embedded object, an encrypted archive) |
| `high` | Directly dangerous (macro project, archive traversal, `/Launch` action) |

**Confidence** — how sure the detector is that it is right:

| | Meaning |
| --- | --- |
| `high` | Structural and unambiguous. A part named `vbaProject.bin` *is* a macro store. |
| `medium` | Strong evidence with known benign causes. |
| `low` | A weak pattern match. Useful as context, never as a verdict on its own. |

Keeping these apart is what lets the tool say *"this might be a problem"*
without saying *"this is a problem"*.

### The four rules

Applied in order. The report always prints which rule fired.

**Rule 1 — Completeness first.** Any finding marked `inspection_incomplete`
means part of the file was not examined: an encrypted archive, a file past the
size limit, a corrupt container, a nesting depth cut off. Such a file can never
be reported as safe. It becomes `COULD NOT FULLY INSPECT` unless something worse
was also found.

**Rule 2 — One decisive finding is enough.** A single `high` severity finding at
`high` or `medium` confidence produces `DO NOT OPEN`. A macro in a Word document
is not a matter of degree.

**Rule 3 — Corroboration promotes to caution.** Two independent `medium`
findings, or a `high`-severity pattern that only reached `low` confidence, or a
single `medium`, produce `REVIEW WITH CAUTION`.

**Rule 4 — Weak signals never escalate alone.** Any number of `low` and `info`
findings reaches caution at most, and one or two `low` findings leave the file
`LIKELY SAFE`. This rule is what stops the tool becoming noise.

### The risk score is for sorting only

`risk_score` (0–100) orders a folder worst-first. It does **not** decide the
verdict — the four rules above do.

```
points(finding) = base[severity] × multiplier[confidence]

base        info 0   low 4   medium 18   high 45
multiplier  low 0.4  medium 0.8  high 1.0
```

Contributions are then **capped per finding code** at twice a single hit. This
is the fix for problem 2 above: 900 identical `archive_executable_member`
findings contribute at most twice what one contributes, so a hostile archive
cannot out-rank a genuine threat by sheer repetition. There is a test for
exactly this (`test_repeated_identical_findings_cannot_inflate_the_score`).

## Worked examples

| Findings | Verdict | Rule |
| --- | --- | --- |
| none | LIKELY SAFE | — |
| one shortened link (`low`/`high`) | LIKELY SAFE | 4 |
| three shortened links + a raw IP | REVIEW WITH CAUTION | 4 |
| embedded OLE object (`medium`/`medium`) | REVIEW WITH CAUTION | 3 |
| appended image data (`medium`) + large metadata (`medium`) | REVIEW WITH CAUTION | 3 |
| macro project (`high`/`high`) | DO NOT OPEN | 2 |
| bomb ratio (`high`/`medium`) | DO NOT OPEN | 2 |
| password-protected archive (`medium`/`high`, incomplete) | REVIEW WITH CAUTION | 3 + 1 |
| corrupt archive only (`low`, incomplete) | COULD NOT FULLY INSPECT | 1 |
| file over the size limit | COULD NOT FULLY INSPECT | 1 |
| macro project **and** an encrypted part | DO NOT OPEN, noted as incomplete | 2 |

## Tuning it

The rules live in `scanner/verdict.py` — about 60 lines, no configuration file,
deliberately. If your school needs different thresholds, change the function and
run `pytest tests/test_verdict.py`; every rule above has a test asserting it.

Individual detector severities live next to the detector that raises them, so a
finding's severity is written beside the evidence that justifies it rather than
in a distant lookup table.

## What the model deliberately does not do

- **No machine learning.** Every verdict must be explainable in a sentence a
  teacher can forward to a parent.
- **No reputation lookups.** Nothing is sent anywhere, so no hash or filename
  leaves the machine.
- **No cross-file inference.** Each file is judged on its own contents. The only
  batch-level signal reported is identical-hash duplicates, and that is
  informational.
