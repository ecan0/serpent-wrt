#!/usr/bin/env python3
"""Behavior tests for the release selection and asset planning helpers."""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import openwrt_release


def write_file(directory: Path, name: str, content: bytes) -> Path:
    path = directory / name
    path.write_bytes(content)
    return path


def digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


class VersionTests(unittest.TestCase):
    def test_final_version_maps_to_itself(self) -> None:
        result = openwrt_release.parse_version("1.0.0")
        self.assertEqual(
            result,
            {
                "package_version": "1.0.0",
                "apk_version": "1.0.0",
                "final": True,
            },
        )

    def test_prerelease_uses_numeric_package_sequence(self) -> None:
        for human, apk in [
            ("0.5.0-rc.1", "0.5.0_pre1"),
            ("1.0.0-beta.2", "1.0.0_pre2"),
            ("1.0.0-rc", "1.0.0_pre1"),
        ]:
            with self.subTest(human=human):
                result = openwrt_release.parse_version(human)
                self.assertEqual(result["apk_version"], apk)
                self.assertFalse(result["final"])

    def test_invalid_versions_are_rejected(self) -> None:
        for value in [
            "",
            "1.0",
            "1.0.0.0",
            "01.0.0",
            "1.0.0-",
            "1.0.0+meta",
            "1.0.0 ",
            "1.0.0-rc..1",
        ]:
            with self.subTest(value=value):
                with self.assertRaises(openwrt_release.ReleaseInputError):
                    openwrt_release.parse_version(value)


class SelectionTests(unittest.TestCase):
    def test_ignores_unrelated_release_notes(self) -> None:
        body = """# Release

Candidate details below.

Serpent-Candidate-Run: 123456
Serpent-Candidate-Digest: sha256:%s
Serpent-Channel: testing

Thanks.
""" % ("a" * 64)
        self.assertEqual(
            openwrt_release.parse_selection(body),
            {
                "run_id": 123456,
                "digest": "sha256:" + "a" * 64,
                "channel": "testing",
            },
        )

    def test_duplicate_and_malformed_keys_fail(self) -> None:
        complete = (
            "Serpent-Candidate-Run: 1\n"
            "Serpent-Candidate-Digest: sha256:" + "b" * 64 + "\n"
            "Serpent-Channel: stable\n"
        )
        cases = {
            "duplicate": complete + "Serpent-Channel: testing\n",
            "missing": "Serpent-Candidate-Run: 1\nSerpent-Channel: stable\n",
            "empty": complete.replace("Serpent-Channel: stable", "Serpent-Channel:"),
            "unknown": complete + "Serpent-Candidate-Other: value\n",
            "uppercase digest": complete.replace("sha256:" + "b" * 64, "SHA256:" + "B" * 64),
            "bare digest": complete.replace("sha256:" + "b" * 64, "b" * 64),
            "short digest": complete.replace("b" * 64, "b" * 63),
            "zero run": complete.replace("Run: 1", "Run: 0"),
            "padded run": complete.replace("Run: 1", "Run: 01"),
            "channel": complete.replace("stable", "beta"),
        }
        for name, body in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(openwrt_release.ReleaseInputError):
                    openwrt_release.parse_selection(body)

    def test_missing_selection_fails(self) -> None:
        with self.assertRaises(openwrt_release.ReleaseInputError):
            openwrt_release.parse_selection("ordinary release notes\n")


class AssetPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_identical_assets_are_skipped(self) -> None:
        write_file(self.directory, "kept.apk", b"kept")
        write_file(self.directory, "new.apk", b"new")
        plan = openwrt_release.plan_asset_upload(
            [
                {"name": "kept.apk", "sha256": digest(b"kept")},
                {"name": "new.apk", "sha256": digest(b"new")},
            ],
            {"assets": [{"name": "kept.apk", "digest": digest(b"kept")}]},
            self.directory,
        )
        self.assertEqual(plan, {"upload": ["new.apk"], "skip": ["kept.apk"]})

    def test_bare_manifest_digests_are_accepted_and_normalized(self) -> None:
        write_file(self.directory, "new.apk", b"new")
        plan = openwrt_release.plan_asset_upload(
            [{"name": "new.apk", "sha256": hashlib.sha256(b"new").hexdigest()}],
            {"assets": []},
            self.directory,
        )
        self.assertEqual(plan, {"upload": ["new.apk"], "skip": []})

    def test_changed_existing_asset_fails(self) -> None:
        write_file(self.directory, "same.apk", b"new bytes")
        with self.assertRaisesRegex(
            openwrt_release.ReleaseInputError, "different bytes"
        ):
            openwrt_release.plan_asset_upload(
                [{"name": "same.apk", "sha256": digest(b"new bytes")}],
                {"assets": [{"name": "same.apk", "digest": digest(b"old bytes")}]},
                self.directory,
            )

    def test_missing_remote_digest_fails_instead_of_guessing(self) -> None:
        write_file(self.directory, "same.apk", b"bytes")
        with self.assertRaisesRegex(openwrt_release.ReleaseInputError, "no digest"):
            openwrt_release.plan_asset_upload(
                [{"name": "same.apk", "sha256": digest(b"bytes")}],
                {"assets": [{"name": "same.apk"}]},
                self.directory,
            )

    def test_candidate_bytes_must_match_the_declared_digest(self) -> None:
        write_file(self.directory, "tampered.apk", b"tampered")
        with self.assertRaisesRegex(
            openwrt_release.ReleaseInputError, "digest mismatch"
        ):
            openwrt_release.plan_asset_upload(
                [{"name": "tampered.apk", "sha256": digest(b"original")}],
                {"assets": []},
                self.directory,
            )

    def test_unsafe_and_duplicate_names_fail(self) -> None:
        write_file(self.directory, "safe.apk", b"bytes")
        cases = [
            [{"name": "../safe.apk", "sha256": digest(b"bytes")}],
            [{"name": "safe.apk", "sha256": digest(b"bytes")},
             {"name": "safe.apk", "sha256": digest(b"bytes")}],
            [{"name": "missing.apk", "sha256": digest(b"bytes")}],
        ]
        for assets in cases:
            with self.subTest(assets=assets):
                with self.assertRaises(openwrt_release.ReleaseInputError):
                    openwrt_release.plan_asset_upload(
                        assets, {"assets": []}, self.directory
                    )


class FileAndBaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_verify_file_and_base_digests(self) -> None:
        path = write_file(self.directory, "candidate.zip", b"archive")
        openwrt_release.verify_file(path, digest(b"archive"))
        with self.assertRaises(openwrt_release.ReleaseInputError):
            openwrt_release.verify_file(path, digest(b"other"))
        openwrt_release.verify_base(digest(b"archive"), path, allow_missing=False)
        with self.assertRaisesRegex(openwrt_release.ReleaseInputError, "stale"):
            openwrt_release.verify_base(digest(b"other"), path, allow_missing=False)
        openwrt_release.verify_base(
            digest(b"archive"), None, allow_missing=False,
            current_digest=digest(b"archive"),
        )
        with self.assertRaisesRegex(openwrt_release.ReleaseInputError, "stale"):
            openwrt_release.verify_base(
                digest(b"archive"), None, allow_missing=False,
                current_digest=digest(b"other"),
            )

    def test_initial_base_requires_authorization_and_absence(self) -> None:
        path = self.directory / "repository-manifest.json"
        with self.assertRaisesRegex(openwrt_release.ReleaseInputError, "explicit"):
            openwrt_release.verify_base(None, path, allow_missing=False)
        openwrt_release.verify_base(None, path, allow_missing=True)
        path.write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(openwrt_release.ReleaseInputError, "exists"):
            openwrt_release.verify_base(None, path, allow_missing=True)

    def test_cli_reports_invalid_selection_without_traceback(self) -> None:
        body = self.directory / "body.txt"
        body.write_text("Serpent-Candidate-Run: 1\n", encoding="utf-8")
        stderr = io.StringIO()
        stdout = io.StringIO()
        with redirect_stderr(stderr), redirect_stdout(stdout):
            status = openwrt_release.main(["parse-selection", "--body-file", str(body)])
        self.assertEqual(status, 1)
        self.assertIn("missing selection lines", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")

    def test_cli_outputs_json(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            status = openwrt_release.main(["version", "--version", "0.5.0-rc.1"])
        self.assertEqual(status, 0)
        self.assertEqual(
            json.loads(stdout.getvalue()),
            {
                "apk_version": "0.5.0_pre1",
                "final": False,
                "package_version": "0.5.0-rc.1",
            },
        )


if __name__ == "__main__":
    unittest.main()
