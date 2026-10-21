#!/usr/bin/env python3
"""Behavior tests for safe candidate archive extraction."""

from __future__ import annotations

import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

import candidate_archive


def build_zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)


class ExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.archive = self.root / "candidate.zip"
        self.output = self.root / "out"

    def test_extracts_regular_files_with_prefix(self) -> None:
        build_zip(
            self.archive,
            [
                ("candidate/candidate.json", b"{}"),
                ("candidate/pages/repository-manifest.json", b"{}"),
            ],
        )
        self.assertEqual(candidate_archive.extract(self.archive, self.output), 2)
        self.assertEqual(
            (self.output / "candidate" / "candidate.json").read_bytes(), b"{}"
        )
        self.assertFalse(self.output.is_symlink())

    def test_traversal_is_rejected_without_output(self) -> None:
        for name in ["../escape", "candidate/../../escape", "/absolute"]:
            with self.subTest(name=name):
                self.output = self.root / f"out-{name.replace('/', '_')}"
                build_zip(self.archive, [("candidate/ok", b"ok"), (name, b"bad")])
                with self.assertRaises(candidate_archive.ArchiveError):
                    candidate_archive.extract(self.archive, self.output)
                self.assertFalse(self.output.exists())

    def test_symlink_member_is_rejected(self) -> None:
        with zipfile.ZipFile(self.archive, "w") as archive:
            member = zipfile.ZipInfo("candidate/link")
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(member, "target")
        with self.assertRaisesRegex(candidate_archive.ArchiveError, "non-regular"):
            candidate_archive.extract(self.archive, self.output)
        self.assertFalse(self.output.exists())

    def test_duplicate_member_is_rejected(self) -> None:
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("candidate/file", b"one")
            archive.writestr("candidate/file", b"two")
        with self.assertRaisesRegex(candidate_archive.ArchiveError, "duplicate"):
            candidate_archive.extract(self.archive, self.output)

    def test_non_empty_output_is_refused(self) -> None:
        self.output.mkdir()
        (self.output / "existing").write_bytes(b"keep")
        build_zip(self.archive, [("candidate/file", b"data")])
        with self.assertRaisesRegex(candidate_archive.ArchiveError, "absent or empty"):
            candidate_archive.extract(self.archive, self.output)
        self.assertEqual((self.output / "existing").read_bytes(), b"keep")

    def test_bad_zip_is_reported(self) -> None:
        self.archive.write_bytes(b"not a zip")
        with self.assertRaises(zipfile.BadZipFile):
            candidate_archive.extract(self.archive, self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
