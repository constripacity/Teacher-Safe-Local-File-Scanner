"""Quarantine utilities for the Teacher-Safe Local File Scanner."""
from __future__ import annotations

import json
import logging
import stat
from datetime import datetime
from pathlib import Path

from . import utils

LOGGER = logging.getLogger(__name__)


def set_read_only(path: Path) -> None:
    """Set read-only permissions for *path*."""
    try:
        mode = path.stat().st_mode
        path.chmod(mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
    except OSError as exc:  # pragma: no cover - platform specific
        LOGGER.warning("Unable to set read-only permissions on %s: %s", path, exc)


def move_to_quarantine(src: Path, dest_dir: Path, *, sha256: str | None = None) -> Path:
    """Move *src* into *dest_dir* in a safe, copy-then-rename fashion."""
    utils.ensure_directory(dest_dir)
    destination = dest_dir / src.name
    temp_destination = dest_dir / f".{src.name}.tmp"
    sha256_value = sha256 or utils.sha256_stream(src)
    original_path = str(src)

    try:
        src.rename(temp_destination)
    except OSError as exc:
        LOGGER.debug("Rename failed for %s, falling back to copy", src)
        utils.copy_file(src, temp_destination)
        original_size = src.stat().st_size
        copied_size = temp_destination.stat().st_size
        if original_size == copied_size:
            src.unlink()
        else:
            temp_destination.unlink(missing_ok=True)
            raise RuntimeError("Failed to move file to quarantine: copy size mismatch") from exc

    temp_destination.rename(destination)
    set_read_only(destination)

    metadata = {
        "original_path": original_path,
        "quarantined_at": datetime.utcnow().isoformat() + "Z",
        "sha256": sha256_value,
    }
    metadata_path = destination.with_suffix(destination.suffix + ".meta.json")
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return destination
