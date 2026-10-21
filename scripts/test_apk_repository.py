#!/usr/bin/env python3
"""Behavioral tests for scripts/apk-repository.py.

These tests use the real pinned SDK host apk and a disposable ECDSA P-256
key.  They exercise the CLI against temporary files and do not mock the
signature or index implementation.  Index trust is proven with real apk
accept/reject checks; package install and upgrade trust remains external
verification F.  Set SERPENT_TEST_SDK to an extracted OpenWrt 25.12 SDK to
run them; otherwise the suite skips.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "apk-repository.py"
SDK_ENV = os.environ.get("SERPENT_TEST_SDK", "")
SDK = Path(SDK_ENV) if SDK_ENV else None
APK = SDK / "staging_dir" / "host" / "bin" / "apk" if SDK else None

ARCHES = {
    "x86/64": "x86_64",
    "x86/generic": "i386_pentium4",
    "mediatek/filogic": "aarch64_cortex-a53",
}
SLUGS = {
    "x86/64": "x86-64",
    "x86/generic": "x86-generic",
    "mediatek/filogic": "mediatek-filogic",
}
SOURCE_COMMIT = "a" * 40
SOURCE_TREE = "b" * 40
HELPER_COMMIT = "c" * 40
WORKFLOW_COMMIT = "d" * 40
PACKAGES_REF = "84f4958aff37296fc77a03b4592ee65ba8b9e7c2"
SDK_URL = "https://downloads.openwrt.org/releases/25.12.5/example-sdk.tar.zst"
SDK_SHA = "f" * 64


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


class RepositoryCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SDK is None:
            raise unittest.SkipTest("SERPENT_TEST_SDK is not set")
        if not APK.is_file():
            raise unittest.SkipTest("SERPENT_TEST_SDK has no host apk")
        if shutil.which("openssl") is None:
            raise unittest.SkipTest("openssl is unavailable")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="serpent-apk-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.key = self.tmp / "signing.pem"
        self.run_ok(
            [
                "openssl",
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                str(self.key),
            ],
            "key generation",
        )

    def run_ok(self, command, label):
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            f"{label} failed:\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return completed

    def cli(self, *arguments):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def make_package(self, bundle, name, version, arch, depends=None, payload=b"x"):
        bundle = Path(bundle)
        bundle.mkdir(parents=True, exist_ok=True)
        root = bundle / f"root-{name}-{arch}"
        (root / "usr" / "bin").mkdir(parents=True, exist_ok=True)
        target = root / "usr" / "bin" / name
        target.write_bytes(payload if isinstance(payload, bytes) else payload.encode())
        target.chmod(0o755)
        output = bundle / f"{name}-{version}.apk"
        command = [
            str(APK),
            "mkpkg",
            "--files",
            str(root),
            "-I",
            f"name:{name}",
            "-I",
            f"version:{version}",
            "-I",
            f"arch:{arch}",
            "-I",
            "description:test package",
            "-I",
            "license:MIT",
            "-o",
            str(output),
        ]
        if depends:
            command.extend(["-I", f"depends:{depends}"])
        self.run_ok(command, f"mkpkg {name}")
        return output

    def make_sbom(self, bundle, filename, component):
        path = Path(bundle) / filename
        path.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "components": [
                        {"type": "library", "name": component, "version": "1"}
                    ],
                }
            ),
            encoding="utf-8",
        )
        return path

    def build_manifest(
        self,
        bundle,
        target,
        slug,
        human,
        apk_path,
        sbom_path,
        source_commit=SOURCE_COMMIT,
        source_tree=SOURCE_TREE,
        helper_commit=HELPER_COMMIT,
        workflow_commit=WORKFLOW_COMMIT,
        package_dir=None,
    ):
        completed = self.cli(
            "build-manifest",
            "--sdk",
            str(SDK),
            "--package-dir",
            str(package_dir or bundle),
            "--output",
            str(Path(bundle) / "manifest.json"),
            "--source-commit",
            source_commit,
            "--source-tree",
            source_tree,
            "--helper-commit",
            helper_commit,
            "--workflow-commit",
            workflow_commit,
            "--package-version",
            human,
            "--target",
            target,
            "--slug",
            slug,
            "--sdk-url",
            SDK_URL,
            "--sdk-sha256",
            SDK_SHA,
            "--packages-ref",
            PACKAGES_REF,
            "--sbom",
            str(sbom_path),
        )
        self.assertEqual(
            completed.returncode,
            0,
            f"build-manifest failed:\n{completed.stdout}\n{completed.stderr}",
        )
        return Path(bundle) / "manifest.json"

    def make_inputs(
        self,
        human,
        apk_version,
        *,
        ui=False,
        targets=None,
        source_commit=SOURCE_COMMIT,
        source_tree=SOURCE_TREE,
        payload_suffix="",
        versions=None,
    ):
        inputs = self.tmp / f"inputs-{human}-{source_commit[:4]}-{payload_suffix or 'base'}"
        targets = list(targets or ARCHES)
        for target in targets:
            slug = SLUGS[target]
            bundle = inputs / slug
            version = (versions or {}).get(target, apk_version)
            apk_path = self.make_package(
                bundle,
                "serpent-wrt",
                version,
                ARCHES[target],
                payload=f"serpent-{target}-{human}-{payload_suffix}".encode(),
            )
            sbom = self.make_sbom(
                bundle, f"serpent-wrt-{version}.cdx.json", "serpent-wrt"
            )
            self.build_manifest(
                bundle,
                target,
                slug,
                human,
                apk_path,
                sbom,
                source_commit=source_commit,
                source_tree=source_tree,
            )
        if ui:
            bundle = inputs / "noarch"
            apk_path = self.make_package(
                bundle,
                "luci-app-serpent",
                apk_version,
                "noarch",
                depends=f"serpent-wrt={apk_version}",
                payload=b"ui",
            )
            sbom = self.make_sbom(
                bundle,
                f"luci-app-serpent-{apk_version}.cdx.json",
                "luci-app-serpent",
            )
            self.build_manifest(
                bundle,
                "all",
                "noarch",
                human,
                apk_path,
                sbom,
                source_commit=source_commit,
                source_tree=source_tree,
            )
        return inputs

    def stage(self, inputs, output, *, channel="testing", previous=None, key=None):
        arguments = [
            "stage",
            "--sdk",
            str(SDK),
            "--inputs",
            str(inputs),
            "--output",
            str(output),
            "--channel",
            channel,
            "--private-key",
            str(key or self.key),
        ]
        if previous is not None:
            arguments.extend(["--previous", str(previous)])
        return self.cli(*arguments)

    def verify(self, root):
        return self.cli("verify", "--sdk", str(SDK), "--root", str(root))

    def stage_ok(self, inputs, output, **kwargs):
        completed = self.stage(inputs, output, **kwargs)
        self.assertEqual(
            completed.returncode,
            0,
            f"stage failed:\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return read_json(Path(output) / "candidate.json")

    def assert_stage_failed_without_output(self, inputs, output, **kwargs):
        completed = self.stage(inputs, output, **kwargs)
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertFalse((Path(output) / "candidate.json").exists())
        if Path(output).exists():
            self.assertEqual(list(Path(output).iterdir()), [])

    def canonical_apks(self, root):
        return sorted((Path(root) / "pages").rglob("*.apk"))

    def index_paths(self, root):
        return sorted((Path(root) / "pages").rglob("packages.adb"))


class LayoutTests(RepositoryCase):
    def test_stage_verify_and_candidate_layout(self):
        inputs = self.make_inputs("0.6.0", "0.6.0-r1")
        output = self.tmp / "candidate"
        candidate = self.stage_ok(inputs, output)

        self.assertEqual(candidate["channel"], "testing")
        self.assertEqual(candidate["apk_version"], "0.6.0-r1")
        self.assertEqual(candidate["source"]["package_version"], "0.6.0")
        self.assertTrue(candidate["prior"]["initial"])
        self.assertIsNone(candidate["prior"]["manifest_sha256"])
        self.assertEqual(len(candidate["packages"]), 3)
        self.assertEqual(
            {entry["target"] for entry in candidate["packages"]},
            set(ARCHES),
        )
        self.assertEqual(
            {item["target"] for item in candidate["sdks"]}, set(ARCHES)
        )

        for entry in candidate["packages"]:
            self.assertEqual(entry["name"], "serpent-wrt")
            self.assertEqual(entry["provenance"], "new")
            self.assertEqual(len(entry["canonical_paths"]), 1)
            canonical = output / entry["canonical_paths"][0]["path"]
            self.assertTrue(canonical.is_file())
            self.assertEqual(
                canonical.name, f"serpent-wrt-0.6.0-r1.apk"
            )
            self.assertEqual(canonical.parent.name, entry["arch"])
            release = output / entry["release"]["path"]
            self.assertEqual(sha256(release), sha256(canonical))
            self.assertTrue((output / entry["sbom"]["path"]).is_file())

        for index in self.index_paths(output):
            self.assertTrue((index.parent / "packages.adb").is_file())
        self.assertTrue((output / "pages" / "serpent-wrt.pem").is_file())
        self.assertTrue((output / "pages" / "serpent-wrt.pem.sha256").is_file())
        self.assertTrue((output / "pages" / "repository-manifest.json").is_file())
        self.assertTrue((output / "checksums" / "SHA256SUMS").is_file())
        self.assertTrue((output / "release" / "SHA256SUMS").is_file())
        self.assertFalse(
            list((output / "pages").rglob("luci-app-serpent-*.apk"))
        )
        self.assertEqual(len(candidate["release_assets"]), 7)

        verified = self.run_ok(
            [
                sys.executable,
                str(SCRIPT),
                "verify",
                "--sdk",
                str(SDK),
                "--root",
                str(output),
            ],
            "verify",
        )
        summary = json.loads(verified.stdout)
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["channel"], "testing")
        self.assertEqual(len(summary["packages"]), 3)

    def test_build_manifest_copies_artifacts_into_bundle(self):
        source = self.tmp / "source"
        bundle = self.tmp / "bundle"
        bundle.mkdir()
        apk_path = self.make_package(source, "serpent-wrt", "0.6.0-r1", "x86_64")
        sbom = self.make_sbom(source, "serpent-wrt-0.6.0-r1.cdx.json", "serpent-wrt")
        self.build_manifest(
            bundle,
            "x86/64",
            "x86-64",
            "0.6.0",
            apk_path,
            sbom,
            package_dir=source,
        )
        bundled_apk = bundle / "serpent-wrt-0.6.0-r1.apk"
        bundled_sbom = bundle / "serpent-wrt-0.6.0-r1.cdx.json"
        self.assertTrue(bundled_apk.is_file())
        self.assertTrue(bundled_sbom.is_file())
        self.assertEqual(sha256(bundled_apk), sha256(apk_path))
        self.assertEqual(sha256(bundled_sbom), sha256(sbom))
        manifest = read_json(bundle / "manifest.json")
        self.assertEqual(manifest["package"]["filename"], bundled_apk.name)
        self.assertEqual(manifest["sbom"]["filename"], bundled_sbom.name)

    def test_build_manifest_rejects_noncanonical_and_bad_inputs(self):
        bundle = self.tmp / "bundle"
        apk_path = self.make_package(bundle, "serpent-wrt", "0.6.0-r1", "x86_64")
        sbom = self.make_sbom(bundle, "serpent-wrt-0.6.0-r1.cdx.json", "serpent-wrt")

        suffixed = bundle / "serpent-wrt-0.6.0-r1-x86-64.apk"
        apk_path.rename(suffixed)
        completed = self.cli(
            "build-manifest",
            "--sdk",
            str(SDK),
            "--package-dir",
            str(bundle),
            "--output",
            str(bundle / "manifest.json"),
            "--source-commit",
            SOURCE_COMMIT,
            "--source-tree",
            SOURCE_TREE,
            "--helper-commit",
            HELPER_COMMIT,
            "--workflow-commit",
            WORKFLOW_COMMIT,
            "--package-version",
            "0.6.0",
            "--target",
            "x86/64",
            "--slug",
            "x86-64",
            "--sdk-url",
            SDK_URL,
            "--sdk-sha256",
            SDK_SHA,
            "--packages-ref",
            PACKAGES_REF,
            "--sbom",
            str(sbom),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((bundle / "manifest.json").exists())

        suffixed.rename(apk_path)
        sbom.write_text("not json", encoding="utf-8")
        completed = self.cli(
            "build-manifest",
            "--sdk",
            str(SDK),
            "--package-dir",
            str(bundle),
            "--output",
            str(bundle / "manifest.json"),
            "--source-commit",
            SOURCE_COMMIT,
            "--source-tree",
            SOURCE_TREE,
            "--helper-commit",
            HELPER_COMMIT,
            "--workflow-commit",
            WORKFLOW_COMMIT,
            "--package-version",
            "0.6.0",
            "--target",
            "x86/64",
            "--slug",
            "x86-64",
            "--sdk-url",
            SDK_URL,
            "--sdk-sha256",
            SDK_SHA,
            "--packages-ref",
            PACKAGES_REF,
            "--sbom",
            str(sbom),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((bundle / "manifest.json").exists())

        outside = self.tmp / "outside.cdx.json"
        outside.write_text(
            json.dumps(
                {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}
            ),
            encoding="utf-8",
        )
        completed = self.cli(
            "build-manifest",
            "--sdk",
            str(SDK),
            "--package-dir",
            str(bundle),
            "--output",
            str(bundle / "manifest.json"),
            "--source-commit",
            SOURCE_COMMIT,
            "--source-tree",
            SOURCE_TREE,
            "--helper-commit",
            HELPER_COMMIT,
            "--workflow-commit",
            WORKFLOW_COMMIT,
            "--package-version",
            "0.6.0",
            "--target",
            "x86/64",
            "--slug",
            "x86-64",
            "--sdk-url",
            SDK_URL,
            "--sdk-sha256",
            SDK_SHA,
            "--packages-ref",
            PACKAGES_REF,
            "--sbom",
            str(outside),
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((bundle / "manifest.json").exists())


class CompletenessTests(RepositoryCase):
    def test_missing_target_and_version_disagreement(self):
        inputs = self.make_inputs(
            "0.6.0", "0.6.0-r1", targets=["x86/64", "x86/generic"]
        )
        self.assert_stage_failed_without_output(inputs, self.tmp / "missing")

        mismatched = self.make_inputs(
            "0.6.0",
            "0.6.0-r1",
            versions={"mediatek/filogic": "0.6.0-r2"},
            payload_suffix="mismatch",
        )
        self.assert_stage_failed_without_output(
            mismatched, self.tmp / "mismatched"
        )

    def test_v0_rejects_ui_and_v1_requires_ui(self):
        v0_ui = self.make_inputs("0.6.0", "0.6.0-r1", ui=True)
        self.assert_stage_failed_without_output(v0_ui, self.tmp / "v0-ui")

        v1_daemon = self.make_inputs(
            "1.0.0", "1.0.0-r1", payload_suffix="v1-daemon"
        )
        self.assert_stage_failed_without_output(v1_daemon, self.tmp / "v1-no-ui")

        v1_ui = self.make_inputs(
            "1.0.0", "1.0.0-r1", ui=True, payload_suffix="v1-ui"
        )
        output = self.tmp / "v1"
        candidate = self.stage_ok(v1_ui, output)
        ui_entries = [
            entry for entry in candidate["packages"] if entry["name"] == "luci-app-serpent"
        ]
        self.assertEqual(len(ui_entries), 1)
        self.assertEqual(len(ui_entries[0]["canonical_paths"]), 3)
        ui_arches = {
            path["path"].split("/")[4] for path in ui_entries[0]["canonical_paths"]
        }
        self.assertEqual(ui_arches, set(ARCHES.values()))
        self.assertEqual(
            ui_entries[0]["release"]["path"],
            "release/luci-app-serpent-1.0.0-r1-noarch.apk",
        )
        self.assertIn(
            "release/luci-app-serpent-1.0.0-r1-noarch.cdx.json",
            {asset["path"] for asset in candidate["release_assets"]},
        )
        self.assertEqual(self.verify(output).returncode, 0)

    def test_stable_requires_final_version(self):
        prerelease = self.make_inputs("1.0.0-rc.1", "1.0.0_pre1-r1", ui=True)
        self.assert_stage_failed_without_output(
            prerelease, self.tmp / "rc", channel="stable"
        )
        candidate = self.stage_ok(prerelease, self.tmp / "rc-testing")
        self.assertEqual(candidate["apk_version"], "1.0.0_pre1-r1")


class ImmutabilityTests(RepositoryCase):
    def test_repeated_build_reuses_bytes_and_refuses_collisions(self):
        inputs = self.make_inputs("0.6.0", "0.6.0-r1")
        first = self.tmp / "first"
        candidate = self.stage_ok(inputs, first)
        original = {
            entry["canonical_paths"][0]["path"]: sha256(
                first / entry["canonical_paths"][0]["path"]
            )
            for entry in candidate["packages"]
        }
        original_indexes = {
            path.relative_to(first).as_posix(): sha256(path)
            for path in self.index_paths(first)
        }

        second = self.tmp / "second"
        repeated = self.stage_ok(
            inputs, second, previous=first / "pages"
        )
        self.assertTrue(all(entry["provenance"] == "reused" for entry in repeated["packages"]))
        for relative, digest in original.items():
            self.assertEqual(sha256(second / relative), digest)
        for relative, digest in original_indexes.items():
            self.assertEqual(sha256(second / relative), digest)
        self.assertEqual(
            repeated["prior"]["manifest_sha256"],
            sha256(first / "pages" / "repository-manifest.json"),
        )

        different_source = self.make_inputs(
            "0.6.0",
            "0.6.0-r1",
            source_commit="1" * 40,
            source_tree="2" * 40,
            payload_suffix="other-source",
        )
        third = self.tmp / "third"
        self.assert_stage_failed_without_output(
            different_source, third, previous=first / "pages"
        )
        for relative, digest in original.items():
            self.assertEqual(sha256(first / relative), digest)

        different_bytes = self.make_inputs(
            "0.6.0", "0.6.0-r1", payload_suffix="different-bytes"
        )
        fourth = self.tmp / "fourth"
        self.assert_stage_failed_without_output(
            different_bytes, fourth, previous=first / "pages"
        )
        for relative, digest in original.items():
            self.assertEqual(sha256(first / relative), digest)

    def test_previous_tree_and_rollback_versions_are_preserved(self):
        old_inputs = self.make_inputs("0.6.0", "0.6.0-r1")
        first = self.tmp / "first"
        old_candidate = self.stage_ok(old_inputs, first)
        old_paths = {
            entry["canonical_paths"][0]["path"]: sha256(
                first / entry["canonical_paths"][0]["path"]
            )
            for entry in old_candidate["packages"]
        }

        new_inputs = self.make_inputs(
            "0.6.1",
            "0.6.1-r1",
            source_commit="3" * 40,
            source_tree="4" * 40,
            payload_suffix="new-version",
        )
        second = self.tmp / "second"
        new_candidate = self.stage_ok(new_inputs, second, previous=first / "pages")

        for relative, digest in old_paths.items():
            self.assertTrue((second / relative).is_file())
            self.assertEqual(sha256(second / relative), digest)
        repository = read_json(second / "pages" / "repository-manifest.json")
        versions = {
            record["version"] for record in repository["packages"]
        }
        self.assertEqual(versions, {"0.6.0-r1", "0.6.1-r1"})
        old_records = [
            record
            for record in repository["packages"]
            if record["version"] == "0.6.0-r1"
        ]
        self.assertTrue(old_records)
        self.assertTrue(
            all(record["source"]["commit"] == SOURCE_COMMIT for record in old_records)
        )
        self.assertTrue(
            all(
                record["source"]["commit"] == "3" * 40
                for record in repository["packages"]
                if record["version"] == "0.6.1-r1"
            )
        )
        release_paths = {asset["path"] for asset in new_candidate["release_assets"]}
        self.assertTrue(any("0.6.1-r1" in path for path in release_paths))
        self.assertFalse(any("0.6.0-r1" in path for path in release_paths))
        self.assertEqual(self.verify(second).returncode, 0)

        for index in self.index_paths(second):
            dumped = self.run_ok(
                [str(APK), "adbdump", "--format", "json", str(index)],
                "index metadata",
            )
            versions = {
                item["version"] for item in json.loads(dumped.stdout)["packages"]
            }
            self.assertEqual(versions, {"0.6.0-r1", "0.6.1-r1"})

    def test_stable_candidate_reuses_testing_bytes(self):
        inputs = self.make_inputs("1.0.0", "1.0.0-r1", ui=True)
        testing = self.tmp / "testing"
        testing_candidate = self.stage_ok(inputs, testing)
        testing_bytes = {
            entry["canonical_paths"][0]["path"]: sha256(
                testing / entry["canonical_paths"][0]["path"]
            )
            for entry in testing_candidate["packages"]
        }

        stable = self.tmp / "stable"
        stable_candidate = self.stage_ok(
            inputs,
            stable,
            channel="stable",
            previous=testing / "pages",
        )
        self.assertEqual(stable_candidate["channel"], "stable")
        self.assertTrue(
            all(entry["provenance"] == "reused" for entry in stable_candidate["packages"])
        )
        for entry in stable_candidate["packages"]:
            self.assertTrue(entry["canonical_paths"][0]["path"].startswith("pages/apk/25.12/stable/"))
        for relative, digest in testing_bytes.items():
            stable_relative = relative.replace("/testing/", "/stable/", 1)
            self.assertEqual(sha256(stable / stable_relative), digest)
            self.assertTrue((stable / relative).is_file())
        self.assertEqual(self.verify(stable).returncode, 0)


class TrustAndFailureTests(RepositoryCase):
    def test_index_trust_accepts_only_the_candidate_key(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "apk_repository_under_test", SCRIPT
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        inputs = self.make_inputs("0.6.0", "0.6.0-r1")
        output = self.tmp / "candidate"
        self.stage_ok(inputs, output)
        index = self.index_paths(output)[0]

        good_keys = self.tmp / "good-keys"
        good_keys.mkdir()
        shutil.copyfile(
            output / "pages" / "serpent-wrt.pem",
            good_keys / "serpent-wrt.pem",
        )
        work = self.tmp / "work"
        work.mkdir()
        module._verify_index_trust(
            str(APK), str(good_keys), str(index), "test index", str(work)
        )

        other_key = self.tmp / "other-index-key.pem"
        self.run_ok(
            [
                "openssl",
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                str(other_key),
            ],
            "other index key",
        )
        bad_keys = self.tmp / "bad-keys"
        bad_keys.mkdir()
        self.run_ok(
            [
                "openssl",
                "pkey",
                "-in",
                str(other_key),
                "-pubout",
                "-out",
                str(bad_keys / "serpent-wrt.pem"),
            ],
            "other public key",
        )
        with self.assertRaises(module.RepositoryError):
            module._verify_index_trust(
                str(APK), str(bad_keys), str(index), "test index", str(work)
            )

    def test_trust_key_mismatch_leaves_prior_unchanged(self):
        inputs = self.make_inputs("0.6.0", "0.6.0-r1")
        first = self.tmp / "first"
        self.stage_ok(inputs, first)
        before = {
            path.relative_to(first).as_posix(): sha256(path)
            for path in first.rglob("*")
            if path.is_file()
        }

        other_key = self.tmp / "other.pem"
        self.run_ok(
            [
                "openssl",
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                str(other_key),
            ],
            "second key",
        )
        completed = self.stage(
            inputs,
            self.tmp / "second",
            previous=first / "pages",
            key=other_key,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("different trust key", completed.stderr)
        after = {
            path.relative_to(first).as_posix(): sha256(path)
            for path in first.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_tampered_previous_package_is_rejected(self):
        inputs = self.make_inputs("0.6.0", "0.6.0-r1")
        first = self.tmp / "first"
        candidate = self.stage_ok(inputs, first)
        victim = first / candidate["packages"][0]["canonical_paths"][0]["path"]
        with open(victim, "ab") as handle:
            handle.write(b"tamper")
        completed = self.stage(
            inputs, self.tmp / "second", previous=first / "pages"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((self.tmp / "second" / "candidate.json").exists())

    def test_verify_detects_tampering_and_missing_trust(self):
        inputs = self.make_inputs("0.6.0", "0.6.0-r1")
        output = self.tmp / "candidate"
        candidate = self.stage_ok(inputs, output)
        self.assertEqual(self.verify(output).returncode, 0)

        canonical = output / candidate["packages"][0]["canonical_paths"][0]["path"]
        original = canonical.read_bytes()
        canonical.write_bytes(original + b"x")
        self.assertNotEqual(self.verify(output).returncode, 0)
        canonical.write_bytes(original)

        index = self.index_paths(output)[0]
        original_index = index.read_bytes()
        index.write_bytes(original_index + b"x")
        self.assertNotEqual(self.verify(output).returncode, 0)
        index.write_bytes(original_index)

        sbom = output / candidate["packages"][0]["sbom"]["path"]
        original_sbom = sbom.read_bytes()
        sbom.write_bytes(original_sbom + b" ")
        self.assertNotEqual(self.verify(output).returncode, 0)
        sbom.write_bytes(original_sbom)

        key = output / "pages" / "serpent-wrt.pem"
        key_backup = key.with_name("serpent-wrt.pem.bak")
        key.rename(key_backup)
        self.assertNotEqual(self.verify(output).returncode, 0)
        key_backup.rename(key)

        renamed = canonical.with_name("serpent-wrt-0.6.0-r1-renamed.apk")
        canonical.rename(renamed)
        self.assertNotEqual(self.verify(output).returncode, 0)
        renamed.rename(canonical)
        self.assertEqual(self.verify(output).returncode, 0)


class PathSafetyTests(RepositoryCase):
    def test_traversal_symlinks_and_output_overlap(self):
        inputs = self.make_inputs("0.6.0", "0.6.0-r1")
        manifest_path = inputs / "x86-64" / "manifest.json"
        manifest = read_json(manifest_path)
        manifest["package"]["filename"] = "../escape.apk"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        shutil.copyfile(
            inputs / "x86-generic" / "serpent-wrt-0.6.0-r1.apk",
            inputs / "escape.apk",
        )
        self.assert_stage_failed_without_output(inputs, self.tmp / "escape-out")

        clean = self.make_inputs(
            "0.6.0", "0.6.0-r1", payload_suffix="symlink"
        )
        link = clean / "manifest-link.json"
        os.symlink(clean / "x86-64" / "manifest.json", link)
        self.assert_stage_failed_without_output(clean, self.tmp / "link-out")

        overlap = self.make_inputs(
            "0.6.0", "0.6.0-r1", payload_suffix="overlap"
        )
        self.assert_stage_failed_without_output(
            overlap, overlap / "candidate"
        )

        key_inside = self.make_inputs(
            "0.6.0", "0.6.0-r1", payload_suffix="key-inside"
        )
        inside_key = key_inside / "signing.pem"
        shutil.copyfile(self.key, inside_key)
        self.assert_stage_failed_without_output(
            key_inside, self.tmp / "key-out", key=inside_key
        )

    def test_prior_tree_symlink_is_rejected(self):
        inputs = self.make_inputs("0.6.0", "0.6.0-r1")
        first = self.tmp / "first"
        self.stage_ok(inputs, first)
        os.symlink(
            first / "pages" / "serpent-wrt.pem",
            first / "pages" / "linked.pem",
        )
        completed = self.stage(
            inputs, self.tmp / "second", previous=first / "pages"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse((self.tmp / "second" / "candidate.json").exists())


if __name__ == "__main__":
    unittest.main()
