"""Platform-capability probes for tests that rely on POSIX-only behaviour.

The tool targets Windows teachers and CI runs ``windows-latest``, so the suite
must stay green there. A handful of checks depend on things Windows cannot host
without elevation — creating a symlink, ``os.geteuid``, ``<``/``>`` in a
filename — so we skip exactly those on platforms that cannot host them, while
still exercising them on Linux and macOS.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

WINDOWS = sys.platform == "win32"


def _symlinks_supported() -> bool:
    """True only if this process can actually create a symlink.

    Probes rather than guessing: Windows with Developer Mode (or an elevated
    CI runner) can create symlinks, and those hosts should run the tests.
    """
    if not hasattr(os, "symlink"):
        return False
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "src"
        src.write_text("probe")
        try:
            (Path(tmp) / "link").symlink_to(src)
        except (OSError, NotImplementedError):
            return False
        return True


SYMLINKS_SUPPORTED = _symlinks_supported()

requires_symlinks = pytest.mark.skipif(
    not SYMLINKS_SUPPORTED,
    reason="creating symlinks is not permitted here (e.g. Windows without Developer Mode)",
)
requires_posix_ids = pytest.mark.skipif(
    not hasattr(os, "geteuid"),
    reason="POSIX-only: needs os.geteuid and chmod-enforced read permission",
)
requires_hostile_filenames = pytest.mark.skipif(
    WINDOWS,
    reason="filenames containing < or > are illegal on NTFS",
)
