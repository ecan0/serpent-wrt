#!/usr/bin/env python3
"""Safely extract a verified candidate artifact ZIP without executing it."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

MAX_ENTRIES = 10000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
SAFE_PART_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@%()\[\]{}~ -]*$")


class ArchiveError(RuntimeError):
    """The candidate archive is unsafe or malformed."""


def _validate_name(name: str) -> str:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise ArchiveError(f"unsafe archive member name: {name!r}")
    parts = name.rstrip("/").split("/")
    for part in parts:
        if part in {"", ".", ".."} or not SAFE_PART_RE.fullmatch(part):
            raise ArchiveError(f"unsafe archive member name: {name!r}")
    return name


def extract(archive: Path, output: Path) -> int:
    if not archive.is_file() or archive.is_symlink():
        raise ArchiveError(f"candidate archive is not a regular file: {archive}")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ArchiveError(f"extraction output must be absent or empty: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.", dir=str(output.parent))
    )
    try:
        with zipfile.ZipFile(archive, "r") as bundle:
            members = bundle.infolist()
            if len(members) > MAX_ENTRIES:
                raise ArchiveError(
                    f"candidate archive has too many members: {len(members)}"
                )
            seen: set[str] = set()
            total = 0
            for member in members:
                _validate_name(member.filename)
                if member.filename in seen:
                    raise ArchiveError(
                        f"duplicate archive member: {member.filename!r}"
                    )
                seen.add(member.filename)
                if member.flag_bits & 0x1:
                    raise ArchiveError(
                        f"encrypted archive member: {member.filename!r}"
                    )
                mode = member.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if member.is_dir():
                    continue
                if file_type not in (0, stat.S_IFREG):
                    raise ArchiveError(
                        f"non-regular archive member: {member.filename!r}"
                    )
                if member.file_size > MAX_FILE_BYTES:
                    raise ArchiveError(
                        f"archive member is too large: {member.filename!r}"
                    )
                total += member.file_size
                if total > MAX_TOTAL_BYTES:
                    raise ArchiveError(
                        f"candidate archive exceeds {MAX_TOTAL_BYTES} bytes"
                    )
                destination = temporary / member.filename
                destination.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member, "r") as source, destination.open(
                    "wb"
                ) as target:
                    written = 0
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > member.file_size:
                            raise ArchiveError(
                                f"archive member exceeds declared size: "
                                f"{member.filename!r}"
                            )
                        target.write(chunk)
                os.chmod(destination, 0o644)
        if output.exists():
            output.rmdir()
        os.replace(temporary, output)
        return len(seen)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    extract_parser = subparsers.add_parser("extract", help="extract an archive")
    extract_parser.add_argument("--archive", required=True, type=Path)
    extract_parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "extract":
            count = extract(args.archive, args.output)
        else:  # pragma: no cover - argparse enforces the choices
            raise ArchiveError(f"unknown command: {args.command}")
    except (ArchiveError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"members": count}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
