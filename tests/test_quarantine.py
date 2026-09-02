"""Quarantine must never delete, never overwrite, and always be reversible."""
from __future__ import annotations

import json
import os
import stat

import pytest

from scanner.quarantine import MANIFEST_NAME, QuarantineError, QuarantineStore, sha256_file
from tests._platform import requires_symlinks


@pytest.fixture()
def store(tmp_path) -> QuarantineStore:
    return QuarantineStore(tmp_path / "quarantine")


def test_two_files_with_the_same_name_do_not_overwrite_each_other(tmp_path, store):
    """Regression: the original used dest/src.name, so the second file
    destroyed the first."""
    a = tmp_path / "a" / "assignment.docx"
    b = tmp_path / "b" / "assignment.docx"
    a.parent.mkdir(parents=True)
    b.parent.mkdir(parents=True)
    a.write_bytes(b"student one")
    b.write_bytes(b"student two")

    entry_a = store.quarantine(a)
    entry_b = store.quarantine(b)

    assert entry_a.stored_name != entry_b.stored_name
    assert (store.root / entry_a.stored_name).read_bytes() == b"student one"
    assert (store.root / entry_b.stored_name).read_bytes() == b"student two"


def test_stored_name_is_not_executable_by_the_shell(tmp_path, store):
    source = tmp_path / "malware.exe"
    source.write_bytes(b"MZ")
    entry = store.quarantine(source)
    assert entry.stored_name.endswith(".quarantined")
    stored = store.root / entry.stored_name
    mode = stored.stat().st_mode
    assert not mode & stat.S_IXUSR
    assert not mode & stat.S_IXGRP
    assert not mode & stat.S_IXOTH


def test_original_is_moved_not_copied(tmp_path, store):
    source = tmp_path / "x.txt"
    source.write_bytes(b"data")
    store.quarantine(source)
    assert not source.exists()


def test_nothing_is_ever_deleted(tmp_path, store):
    source = tmp_path / "x.txt"
    source.write_bytes(b"important")
    entry = store.quarantine(source)
    assert (store.root / entry.stored_name).read_bytes() == b"important"


@requires_symlinks
def test_symlinks_are_refused(tmp_path, store):
    real = tmp_path / "real.txt"
    real.write_bytes(b"x")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    with pytest.raises(QuarantineError, match="symbolic link"):
        store.quarantine(link)
    assert real.exists()


def test_restore_returns_the_file_to_its_original_path(tmp_path, store):
    source = tmp_path / "sub" / "essay.docx"
    source.parent.mkdir()
    source.write_bytes(b"my essay")
    entry = store.quarantine(source)
    restored = store.restore(entry.entry_id)
    assert restored == source
    assert restored.read_bytes() == b"my essay"


def test_restore_can_target_a_different_folder(tmp_path, store):
    source = tmp_path / "essay.docx"
    source.write_bytes(b"content")
    entry = store.quarantine(source)
    elsewhere = tmp_path / "reviewed"
    elsewhere.mkdir()
    restored = store.restore(entry.entry_id, destination=elsewhere)
    assert restored == elsewhere / "essay.docx"


def test_restore_refuses_to_overwrite(tmp_path, store):
    source = tmp_path / "essay.docx"
    source.write_bytes(b"original")
    entry = store.quarantine(source)
    source.write_bytes(b"a newer file with the same name")
    with pytest.raises(QuarantineError, match="already exists"):
        store.restore(entry.entry_id)
    assert source.read_bytes() == b"a newer file with the same name"


def test_restore_twice_is_refused(tmp_path, store):
    source = tmp_path / "essay.docx"
    source.write_bytes(b"content")
    entry = store.quarantine(source)
    store.restore(entry.entry_id)
    with pytest.raises(QuarantineError, match="already restored"):
        store.restore(entry.entry_id)


def test_restore_detects_tampering(tmp_path, store):
    source = tmp_path / "essay.docx"
    source.write_bytes(b"content")
    entry = store.quarantine(source)
    stored = store.root / entry.stored_name
    stored.chmod(0o600)
    stored.write_bytes(b"something else entirely")
    with pytest.raises(QuarantineError, match="no longer matches"):
        store.restore(entry.entry_id)


def test_manifest_is_append_only_jsonl(tmp_path, store):
    for name in ("a.txt", "b.txt"):
        path = tmp_path / name
        path.write_bytes(name.encode())
        store.quarantine(path, reason="test")
    lines = (store.root / MANIFEST_NAME).read_text().strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        record = json.loads(line)
        assert record["sha256"] and record["original_path"] and record["quarantined_at"]


def test_manifest_survives_a_corrupt_line(tmp_path, store):
    path = tmp_path / "a.txt"
    path.write_bytes(b"a")
    store.quarantine(path)
    with (store.root / MANIFEST_NAME).open("a") as handle:
        handle.write("{not json at all\n")
    assert len(store.entries()) == 1


def test_hash_recorded_matches_the_stored_file(tmp_path, store):
    path = tmp_path / "a.bin"
    path.write_bytes(b"\x00\x01\x02")
    entry = store.quarantine(path)
    assert sha256_file(store.root / entry.stored_name) == entry.sha256


def test_quarantine_directory_is_not_world_readable(store):
    if os.name == "nt":  # pragma: no cover
        pytest.skip("POSIX permissions only")
    mode = store.root.stat().st_mode
    assert not mode & stat.S_IROTH
    assert not mode & stat.S_IRGRP


def test_unknown_entry_id_is_an_error(store):
    with pytest.raises(QuarantineError, match="No quarantine entry"):
        store.restore("deadbeef")
