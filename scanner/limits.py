"""Resource limits for static inspection.

Every detector in this project reads attacker-controlled bytes. The original
implementation called ``f.read()`` with no bound and walked ZIP central
directories with no member cap, which turns a 40 KB submission into an
out-of-memory kill (a decompression bomb) on a teacher's laptop.

:class:`ScanLimits` is the single place those bounds are declared, so that a
reviewer can read one struct and know exactly what the scanner will refuse to do.
"""
from __future__ import annotations

from dataclasses import dataclass

KB = 1024
MB = 1024 * KB


@dataclass(frozen=True)
class ScanLimits:
    """Hard ceilings applied to every file, regardless of detector."""

    #: Files larger than this are not read at all (they are reported as
    #: COULD NOT FULLY INSPECT rather than silently passed as safe).
    max_file_size: int = 100 * MB

    #: Largest slice any detector may hold in memory at once.
    max_read_bytes: int = 8 * MB

    #: Bytes scanned from the head/tail of a file for signature work.
    head_bytes: int = 64 * KB
    tail_bytes: int = 256 * KB

    #: ZIP / OOXML central-directory limits.
    max_archive_members: int = 5_000
    max_archive_depth: int = 3
    max_total_uncompressed: int = 512 * MB

    #: Ratio of declared uncompressed size to compressed size above which an
    #: entry is treated as a decompression-bomb indicator. Text and logs
    #: legitimately reach ~100:1; 200:1 keeps false positives rare.
    max_compression_ratio: float = 200.0

    #: Bytes actually decompressed when a nested archive must be opened. Nested
    #: archives are only ever read through a bounded stream, never extracted to
    #: disk.
    max_nested_extract_bytes: int = 16 * MB

    #: Cap on findings retained per file, to keep reports and memory bounded
    #: when a hostile archive contains 100k suspicious members.
    max_findings_per_file: int = 200

    #: Cap on URL extraction work for text-like files.
    max_text_scan_bytes: int = 512 * KB
    max_urls_reported: int = 25

    def with_max_file_size(self, value: int) -> "ScanLimits":
        return ScanLimits(**{**self.__dict__, "max_file_size": max(1, int(value))})


DEFAULT_LIMITS = ScanLimits()

__all__ = ["ScanLimits", "DEFAULT_LIMITS", "KB", "MB"]
