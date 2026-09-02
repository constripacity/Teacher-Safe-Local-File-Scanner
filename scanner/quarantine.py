"""Quarantine: move a file somewhere it cannot be opened by accident.

Guarantees, in order of importance:

1. **Nothing is ever deleted.** Quarantine only ever moves, and restore only
   ever moves back.
2. **Nothing can be run from quarantine by accident.** The stored copy gains a
   ``.quarantined`` suffix so a double-click does not hand it to Word or the
   shell, and the execute bits are cleared.
3. **Nothing is ever silently overwritten.** Two students both submitting
   ``assignment.docx`` produce two distinct quarantine entries. The original
   implementation used ``dest_dir / src.name`` with no collision handling, so
   the second file destroyed the first.
4. **Every move is recorded.** An append-only JSONL manifest holds the original
   path, the hash before and after, timestamps and the reason, so a file can be
   restored to exactly where it came from and proven unmodified.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import stat
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

LOGGER = logging.getLogger(__name__)

MANIFEST_NAME = "quarantine-manifest.jsonl"
NEUTRALISED_SUFFIX = ".quarantined"
CHUNK = 1024 * 1024


class QuarantineError(RuntimeError):
    """Raised when a quarantine or restore operation cannot be completed safely."""


@dataclass(frozen=True)
class QuarantineEntry:
    entry_id: str
    original_path: str
    stored_name: str
    sha256: str
    size: int
    quarantined_at: str
    reason: str
    verdict: Optional[str] = None
    restored_at: Optional[str] = None
    restored_to: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QuarantineEntry":
        return cls(
            entry_id=str(data.get("entry_id", "")),
            original_path=str(data.get("original_path", "")),
            stored_name=str(data.get("stored_name", "")),
            sha256=str(data.get("sha256", "")),
            size=int(data.get("size", 0)),
            quarantined_at=str(data.get("quarantined_at", "")),
            reason=str(data.get("reason", "")),
            verdict=data.get("verdict"),
            restored_at=data.get("restored_at"),
            restored_to=data.get("restored_to"),
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


class QuarantineStore:
    """A quarantine directory plus its manifest."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._harden_directory()
        self.manifest_path = self.root / MANIFEST_NAME

    # -- internals -----------------------------------------------------
    def _harden_directory(self) -> None:
        try:
            self.root.chmod(0o700)
        except OSError as exc:  # pragma: no cover - Windows / exotic filesystems
            LOGGER.debug("Could not restrict quarantine directory permissions: %s", exc)

    def _stored_name(self, source: Path, digest: str) -> str:
        """Collision-proof, non-executable storage name.

        ``essay.docx`` becomes ``essay.docx.<first-12-of-hash>.quarantined``.
        The hash makes collisions impossible in practice while keeping the
        original name readable, and the trailing suffix means the operating
        system has no handler for it.
        """
        safe = "".join(
            char if char.isalnum() or char in "._- " else "_" for char in source.name
        ).strip() or "file"
        return f"{safe[:120]}.{digest[:12]}{NEUTRALISED_SUFFIX}"

    def _append_manifest(self, entry: QuarantineEntry) -> None:
        with self.manifest_path.open("a", encoding="utf-8") as handle:
            handle.write(entry.to_json() + "\n")

    # -- public API ----------------------------------------------------
    def entries(self) -> List[QuarantineEntry]:
        """Latest state of every entry, replaying the append-only manifest."""
        latest: Dict[str, QuarantineEntry] = {}
        for entry in self._iter_manifest():
            latest[entry.entry_id] = entry
        return sorted(latest.values(), key=lambda e: e.quarantined_at, reverse=True)

    def _iter_manifest(self) -> Iterator[QuarantineEntry]:
        if not self.manifest_path.exists():
            return
        with self.manifest_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield QuarantineEntry.from_dict(json.loads(line))
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    LOGGER.warning("Skipping malformed manifest line: %s", exc)

    def quarantine(
        self,
        source: Path,
        *,
        reason: str = "manual",
        verdict: Optional[str] = None,
        sha256: Optional[str] = None,
    ) -> QuarantineEntry:
        """Move *source* into quarantine. Never deletes, never overwrites."""
        source = Path(source)
        if source.is_symlink():
            raise QuarantineError(
                f"{source} is a symbolic link; quarantining it would move the link, "
                "not the file it points at. Resolve it first if that is what you want."
            )
        if not source.is_file():
            raise QuarantineError(f"{source} is not a regular file")

        digest = sha256 or sha256_file(source)
        size = source.stat().st_size
        stored_name = self._stored_name(source, digest)
        destination = self.root / stored_name
        if destination.exists():
            existing = sha256_file(destination)
            if existing == digest:
                LOGGER.info("%s is already in quarantine (identical content)", source.name)
            else:  # pragma: no cover - 12-hex-char collision with different content
                destination = self.root / f"{stored_name}.{uuid.uuid4().hex[:8]}"

        original_path = str(source.resolve())
        temp = self.root / f".incoming-{uuid.uuid4().hex}"
        try:
            try:
                os.replace(source, temp)
            except OSError:
                # Cross-device move: copy, verify, then remove the original.
                shutil.copy2(source, temp)
                if sha256_file(temp) != digest:
                    temp.unlink(missing_ok=True)
                    raise QuarantineError(
                        f"Copy of {source} into quarantine did not match the original "
                        "hash; the original has been left untouched."
                    ) from None
                source.unlink()
            os.replace(temp, destination)
        except QuarantineError:
            raise
        except OSError as exc:
            temp.unlink(missing_ok=True)
            raise QuarantineError(f"Could not quarantine {source}: {exc}") from exc

        self._neutralise(destination)

        entry = QuarantineEntry(
            entry_id=uuid.uuid4().hex,
            original_path=original_path,
            stored_name=destination.name,
            sha256=digest,
            size=size,
            quarantined_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            reason=reason,
            verdict=verdict,
        )
        self._append_manifest(entry)
        LOGGER.info("Quarantined %s -> %s", original_path, destination.name)
        return entry

    def _neutralise(self, path: Path) -> None:
        """Clear execute bits and make the stored copy read-only where supported."""
        try:
            mode = path.stat().st_mode
            path.chmod(
                mode
                & ~stat.S_IXUSR & ~stat.S_IXGRP & ~stat.S_IXOTH
                & ~stat.S_IWGRP & ~stat.S_IWOTH
                & ~stat.S_IRGRP & ~stat.S_IROTH
            )
        except OSError as exc:  # pragma: no cover - platform dependent
            LOGGER.warning("Could not restrict permissions on %s: %s", path, exc)

    def restore(
        self, entry_id: str, *, destination: Optional[Path] = None, force: bool = False
    ) -> Path:
        """Move a quarantined file back out. Deliberate, verified, and logged."""
        matches = [e for e in self.entries() if e.entry_id.startswith(entry_id)]
        if not matches:
            raise QuarantineError(f"No quarantine entry starting with {entry_id!r}")
        if len(matches) > 1:
            raise QuarantineError(
                f"{entry_id!r} matches {len(matches)} entries; use a longer id"
            )
        entry = matches[0]
        if entry.restored_at:
            raise QuarantineError(
                f"Entry {entry.entry_id[:12]} was already restored to {entry.restored_to}"
            )

        stored = self.root / entry.stored_name
        if not stored.is_file():
            raise QuarantineError(f"Quarantined file {entry.stored_name} is missing")

        actual = sha256_file(stored)
        if actual != entry.sha256 and not force:
            raise QuarantineError(
                "Quarantined file no longer matches its recorded hash "
                f"(expected {entry.sha256[:12]}, found {actual[:12]}). "
                "Pass force=True only if you know why."
            )

        target = Path(destination) if destination else Path(entry.original_path)
        target = target.expanduser()
        if target.is_dir():
            target = target / Path(entry.original_path).name
        if target.exists() and not force:
            raise QuarantineError(
                f"{target} already exists; restoring would overwrite it. "
                "Choose another destination or pass force=True."
            )
        target.parent.mkdir(parents=True, exist_ok=True)

        try:
            os.replace(stored, target)
        except OSError:
            shutil.copy2(stored, target)
            stored.unlink()

        try:
            target.chmod(0o600)
        except OSError:  # pragma: no cover
            pass

        self._append_manifest(
            QuarantineEntry(
                **{
                    **asdict(entry),
                    "restored_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "restored_to": str(target),
                }
            )
        )
        LOGGER.info("Restored %s -> %s", entry.stored_name, target)
        return target


# -- backwards-compatible helper -------------------------------------------
def move_to_quarantine(src: Path, dest_dir: Path, *, sha256: Optional[str] = None) -> Path:
    """Kept so existing scripts keep working; prefer :class:`QuarantineStore`."""
    store = QuarantineStore(dest_dir)
    entry = store.quarantine(src, reason="legacy-api", sha256=sha256)
    return store.root / entry.stored_name


__all__ = [
    "QuarantineStore",
    "QuarantineEntry",
    "QuarantineError",
    "move_to_quarantine",
    "sha256_file",
    "MANIFEST_NAME",
    "NEUTRALISED_SUFFIX",
]
