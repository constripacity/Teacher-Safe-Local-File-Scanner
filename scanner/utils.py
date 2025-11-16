"""Utility helpers for the Teacher-Safe Local File Scanner.

This module provides pure helper utilities shared across the project. The
functions defined here do **not** execute untrusted content and are limited to
reading metadata, hashes, and small sections of files.
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
from pathlib import Path
from typing import Iterator

LOGGER = logging.getLogger(__name__)


CHUNK_SIZE = 1024 * 1024


def sha256_stream(path: Path) -> str:
    """Return the SHA256 digest of *path* using a streaming read."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_read_head(path: Path, nbytes: int) -> bytes:
    """Read up to *nbytes* bytes from the beginning of *path* safely."""
    try:
        with path.open("rb") as handle:
            return handle.read(nbytes)
    except (OSError, IOError) as exc:  # pragma: no cover - exercised indirectly
        LOGGER.warning("Unable to read head of %s: %s", path, exc)
        return b""


def safe_read_tail(path: Path, nbytes: int) -> bytes:
    """Read the last *nbytes* bytes of *path* without loading the file."""
    try:
        size = path.stat().st_size
    except OSError as exc:  # pragma: no cover - exercised indirectly
        LOGGER.warning("Unable to stat %s: %s", path, exc)
        return b""
    if size == 0:
        return b""
    offset = max(size - nbytes, 0)
    try:
        with path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(nbytes)
    except (OSError, IOError) as exc:  # pragma: no cover
        LOGGER.warning("Unable to read tail of %s: %s", path, exc)
        return b""


MAGIC_SIGNATURES = {
    b"%PDF": "pdf",
    b"PK\x03\x04": "zip",
    b"PK\x05\x06": "zip",
    b"PK\x07\x08": "zip",
    b"\xFF\xD8\xFF": "jpeg",
    b"\x89PNG\r\n\x1A\n": "png",
    b"MZ": "pe",
}


try:  # pragma: no cover - optional dependency
    import magic
except ImportError:  # pragma: no cover - no optional dep in tests
    magic = None
    import magic  # type: ignore
except ImportError:  # pragma: no cover - no optional dep in tests
    magic = None  # type: ignore


def detect_magic_type(path: Path, *, use_magic: bool = False) -> str:
    """Detect the file type using python-magic if enabled, otherwise magic bytes."""
    if use_magic and magic is not None:
        try:
            mime = magic.from_file(str(path), mime=True)
            return mime or "unknown"
        except Exception as exc:  # pragma: no cover - optional path
            LOGGER.debug("python-magic failed for %s: %s", path, exc)
    head = safe_read_head(path, 16)
    for signature, label in MAGIC_SIGNATURES.items():
        if head.startswith(signature):
            return label
    return "unknown"


def is_text_file(path: Path, *, max_bytes: int = 4096) -> bool:
    """Heuristic to decide whether *path* appears to be text."""
    head = safe_read_head(path, max_bytes)
    if not head:
        return False
    if b"\x00" in head:
        return False
    try:
        head.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def safe_list_zip_members(path: Path) -> list[str]:
    """Return the member list of a zip archive, handling corruption gracefully."""
    import zipfile

    members: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                members.append(info.filename)
    except zipfile.BadZipFile as exc:
        LOGGER.warning("Corrupt ZIP %s: %s", path, exc)
    except OSError as exc:
        LOGGER.warning("Unable to open ZIP %s: %s", path, exc)
    return members


def iter_directory_files(root: Path) -> Iterator[Path]:
    """Yield files within *root* recursively."""
    if root.is_file():
        yield root
        return
    for dirpath, _, filenames in os.walk(root):
        base = Path(dirpath)
        for filename in filenames:
            yield base / filename


def copy_file(src: Path, dest: Path) -> None:
    """Copy *src* to *dest* using buffered IO."""
    with src.open("rb") as source, dest.open("wb") as target:
        shutil.copyfileobj(source, target, length=CHUNK_SIZE)


def ensure_directory(path: Path) -> None:
    """Ensure *path* exists as a directory."""
    path.mkdir(parents=True, exist_ok=True)
