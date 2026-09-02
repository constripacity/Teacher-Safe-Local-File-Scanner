#!/usr/bin/env python3
"""Build a standalone executable and write a checksum next to it.

Usage:
    pip install -e ".[build]"
    python scripts/build_binary.py

The checksum is the point: a security tool distributed as a binary that nobody
can verify is a security problem, not a security product.
"""
from __future__ import annotations

import hashlib
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    if shutil.which("pyinstaller") is None:
        print("pyinstaller not found. Install it with: pip install -e '.[build]'", file=sys.stderr)
        return 1

    print("Building…")
    result = subprocess.run(
        ["pyinstaller", "--noconfirm", "--clean", "teacher-safe-scan.spec"],
        cwd=ROOT,
    )
    if result.returncode != 0:
        return result.returncode

    suffix = ".exe" if platform.system() == "Windows" else ""
    binary = ROOT / "dist" / f"teacher-safe-scan{suffix}"
    if not binary.exists():
        print(f"expected {binary} but it was not produced", file=sys.stderr)
        return 1

    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    label = f"{platform.system().lower()}-{platform.machine().lower()}"
    checksum_file = binary.with_name(f"{binary.name}.sha256")
    checksum_file.write_text(f"{digest}  {binary.name}\n", encoding="utf-8")

    size_mb = binary.stat().st_size / (1024 * 1024)
    print(f"\n  {binary}  ({size_mb:.1f} MB, {label})")
    print(f"  sha256  {digest}")
    print(f"  written to {checksum_file}")
    print(
        "\n  This binary is UNSIGNED. macOS Gatekeeper will block it until it is\n"
        "  signed and notarised with an Apple Developer ID; Windows SmartScreen\n"
        "  will warn. Do not describe it as signed in release notes."
    )

    print("\n  Smoke test:")
    smoke = subprocess.run([str(binary), "--version"], capture_output=True, text=True)
    print("   ", smoke.stdout.strip() or smoke.stderr.strip())
    return smoke.returncode


if __name__ == "__main__":
    raise SystemExit(main())
