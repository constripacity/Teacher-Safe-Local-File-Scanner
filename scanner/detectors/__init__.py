"""Static detectors.

Every detector in this package obeys two invariants:

1. **Nothing is executed.** No macro runs, no PDF is rendered, no archive is
   extracted to disk, no image is decoded.
2. **Nothing is unbounded.** Reads, recursion depth, member counts and finding
   counts are all capped by :class:`scanner.limits.ScanLimits`.

Each detector returns :class:`scanner.findings.Finding` objects carrying their
own evidence, plain-English explanation, and recommended action, so a report can
justify every line it prints.
"""
from __future__ import annotations

from .archive import analyze_archive
from .general import analyze_content, analyze_name, analyze_text_urls
from .image import analyze_image
from .office import HAVE_DEFUSEDXML, analyze_office
from .pdf import analyze_pdf

__all__ = [
    "analyze_archive",
    "analyze_image",
    "analyze_office",
    "analyze_pdf",
    "analyze_name",
    "analyze_content",
    "analyze_text_urls",
    "HAVE_DEFUSEDXML",
]
