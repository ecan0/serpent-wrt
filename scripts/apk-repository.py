#!/usr/bin/env python3
"""Build, sign, stage, and verify the Serpent OpenWrt APK repository.

This helper is intentionally self-contained.  The workflow invokes the CLI
below; it must never reimplement manifest, signature, or immutability rules.

Commands
--------
build-manifest
    Read an unsigned canonical APK and its SBOM and write the build manifest
    that a later staging job consumes.

stage
    Validate all build manifests and the previous Pages tree, sign new
    packages exactly once, create canonical per-architecture indexes, and
    write an atomic verified candidate directory.

verify
    Read-only verification of a candidate directory.  It validates the
    signed index with the published key (accept) and without it (reject),
    canonical index filename resolution, package metadata and digests,
    checksums, provenance, and target completeness.  Package-manager install
    and upgrade trust is external verification F; package-level ``apk verify``
    is not used as a trust gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

SCHEMA_VERSION = 1
DAEMON_NAME = "serpent-wrt"
UI_NAME = "luci-app-serpent"
CHANNELS = ("testing", "stable")
EXPECTED_TARGETS = {
    "x86/64": "x86-64",
    "x86/generic": "x86-generic",
    "mediatek/filogic": "mediatek-filogic",
}
UI_TARGET = ("all", "noarch")
REPOSITORY_ROOT = "apk/25.12"
PUBLIC_KEY_NAME = "serpent-wrt.pem"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_REPOSITORY_BYTES = 16 * 1024 * 1024
MAX_CANDIDATE_BYTES = 16 * 1024 * 1024
MAX_SBOM_BYTES = 64 * 1024 * 1024

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]*$")
SAFE_PATH_COMPONENT = re.compile(r"^[A-Za-z0-9._+~-]+$")
HUMAN_VERSION = re.compile(
    r"^([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z][0-9A-Za-z.+-]*))?$"
)
PRIVATE_PATTERNS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)


class RepositoryError(Exception):
    """A user-facing validation or tool failure."""


def fail(message):
    raise RepositoryError(message)


# ---------------------------------------------------------------------------
# Small filesystem and process helpers
# ---------------------------------------------------------------------------


def _require_regular(path, label):
    path = os.fspath(path)
    try:
        info = os.lstat(path)
    except OSError as exc:
        fail(f"{label} is missing or unreadable: {exc.strerror}")
    if stat.S_ISLNK(info.st_mode):
        fail(f"{label} must not be a symbolic link")
    if not stat.S_ISREG(info.st_mode):
        fail(f"{label} must be a regular file")
    return path


def _require_directory(path, label):
    path = os.fspath(path)
    try:
        info = os.lstat(path)
    except OSError as exc:
        fail(f"{label} is missing or unreadable: {exc.strerror}")
    if stat.S_ISLNK(info.st_mode):
        fail(f"{label} must not be a symbolic link")
    if not stat.S_ISDIR(info.st_mode):
        fail(f"{label} must be a directory")
    return path


def _missing(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError as exc:
        fail(f"unable to inspect {os.path.basename(path)}: {exc.strerror}")
    return False


def _contained(path, root):
    path = os.path.realpath(path)
    root = os.path.realpath(root)
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def _check_no_symlinks(root, label):
    root = _require_directory(root, label)
    for current, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories):
            full = os.path.join(current, name)
            if os.path.islink(full):
                fail(f"{label} contains a symbolic link")
        for name in sorted(files):
            full = os.path.join(current, name)
            if os.path.islink(full):
                fail(f"{label} contains a symbolic link")
    return root


def _safe_component(value, label):
    if not isinstance(value, str) or not SAFE_COMPONENT.fullmatch(value):
        fail(f"{label} is not a safe filename component")
    return value


def _safe_relative(value, label, *, basename_only=False):
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty relative path")
    if value.startswith("/") or "\\" in value or "\x00" in value:
        fail(f"{label} must be a relative POSIX path")
    parts = value.split("/")
    if basename_only and len(parts) != 1:
        fail(f"{label} must be a plain filename")
    for part in parts:
        if part in ("", ".", ".."):
            fail(f"{label} contains a traversal component")
        if not SAFE_PATH_COMPONENT.fullmatch(part):
            fail(f"{label} contains an unsafe path component")
    return value


def _join_contained(root, relative, label, *, basename_only=False):
    relative = _safe_relative(relative, label, basename_only=basename_only)
    full = os.path.join(root, *relative.split("/"))
    if not _contained(full, root):
        fail(f"{label} escapes its allowed directory")
    return full


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _read_bytes(path, label, limit):
    _require_regular(path, label)
    size = os.path.getsize(path)
    if size > limit:
        fail(f"{label} exceeds the supported size limit")
    with open(path, "rb") as handle:
        return handle.read()


def _write_atomic(path, data, mode=0o644):
    directory = os.path.dirname(path) or "."
    if not os.path.isdir(directory):
        fail(f"output directory for {os.path.basename(path)} is missing")
    if os.path.islink(path):
        fail(f"{os.path.basename(path)} must not be a symbolic link")
    descriptor, temporary = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_json(path, value):
    _write_atomic(path, _json_bytes(value))


def _read_json(path, label, limit):
    raw = _read_bytes(path, label, limit)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is not valid JSON")
    if not isinstance(value, dict):
        fail(f"{label} must contain a JSON object")
    return value, raw


def _copy_file(source, destination):
    if os.path.islink(source):
        fail("refusing to copy a symbolic link")
    if not _missing(destination) and os.path.islink(destination):
        fail("refusing to overwrite a symbolic link")
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o644)


def _copy_tree(source, destination):
    source = _check_no_symlinks(source, "previous Pages tree")
    os.makedirs(destination, exist_ok=True)
    for current, directories, files in os.walk(source, followlinks=False):
        directories.sort()
        relative = os.path.relpath(current, source)
        target_dir = destination if relative == "." else os.path.join(destination, relative)
        os.makedirs(target_dir, exist_ok=True)
        for name in sorted(files):
            full = os.path.join(current, name)
            if os.path.islink(full):
                fail("previous Pages tree contains a symbolic link")
            if not os.path.isfile(full):
                fail("previous Pages tree contains a non-regular file")
            target = os.path.join(target_dir, name)
            shutil.copyfile(full, target)
            os.chmod(target, 0o644)


def _files_under(root):
    result = []
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        for name in sorted(files):
            full = os.path.join(current, name)
            if os.path.islink(full):
                fail("refusing a symbolic link in candidate output")
            if not os.path.isfile(full):
                fail("candidate output contains a non-regular file")
            result.append(os.path.relpath(full, root).replace(os.sep, "/"))
    return sorted(result)


def _run(command, *, label, env=None, allow_failure=False):
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            check=False,
            env=run_env,
        )
    except FileNotFoundError:
        fail(f"{label} executable is unavailable")
    except OSError as exc:
        fail(f"{label} could not be executed: {exc.strerror}")
    output = completed.stderr.decode("utf-8", "replace").strip()
    if completed.returncode != 0 and not allow_failure:
        detail = output.splitlines()[-1] if output else "no diagnostic"
        fail(f"{label} failed: {detail}")
    return completed


# ---------------------------------------------------------------------------
# Version and schema rules
# ---------------------------------------------------------------------------


def _parse_human_version(value, label="package version"):
    if not isinstance(value, str):
        fail(f"{label} must be a string")
    match = HUMAN_VERSION.fullmatch(value)
    if not match:
        fail(f"{label} must use x.y.z or x.y.z-prerelease syntax")
    major = int(match.group(1))
    prerelease = match.group(4)
    return major, prerelease


def _expected_apk_prefix(human):
    match = HUMAN_VERSION.fullmatch(human)
    if not match:
        fail("package version must use x.y.z or x.y.z-prerelease syntax")
    base = f"{match.group(1)}.{match.group(2)}.{match.group(3)}"
    prerelease = match.group(4)
    if not prerelease:
        return base
    sequence = prerelease.rsplit(".", 1)[-1]
    if not sequence.isdigit():
        sequence = "1"
    return f"{base}_pre{sequence}"


def _validate_apk_version(human, apk_version):
    prefix = _expected_apk_prefix(human)
    if not re.fullmatch(re.escape(prefix) + r"-r[0-9]+", apk_version or ""):
        fail(
            "APK version does not match the source version and PKG_RELEASE mapping"
        )


def _major_version(human):
    return _parse_human_version(human)[0]


def _is_prerelease(human):
    return bool(_parse_human_version(human)[1])


def _check_object(value, label, required, optional=()):
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    missing = sorted(set(required) - set(value))
    extra = sorted(set(value) - set(required) - set(optional))
    if missing:
        fail(f"{label} is missing required field(s): {', '.join(missing)}")
    if extra:
        fail(f"{label} has unsupported field(s): {', '.join(extra)}")


def _check_hash(value, label, pattern=HEX64):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        fail(f"{label} must be a lowercase hexadecimal SHA-256")
    return value


def _check_positive_int(value, label):
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(f"{label} must be a positive integer")
    return value


def _check_nonnegative_int(value, label):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        fail(f"{label} must be a non-negative integer")
    return value


def _check_source(value, label, package_version_required=True):
    keys = {"commit", "tree"}
    if package_version_required:
        keys.add("package_version")
    _check_object(value, label, keys)
    if not isinstance(value["commit"], str) or not GIT_OBJECT.fullmatch(value["commit"]):
        fail(f"{label} commit must be a Git object id")
    if not isinstance(value["tree"], str) or not GIT_OBJECT.fullmatch(value["tree"]):
        fail(f"{label} tree must be a Git object id")
    if package_version_required:
        _parse_human_version(value["package_version"], f"{label} package version")


def _check_sdk(value, label):
    _check_object(value, label, {"url", "sha256"})
    if not isinstance(value["url"], str) or not value["url"].startswith("https://"):
        fail(f"{label} URL must be an HTTPS URL")
    _check_hash(value["sha256"], f"{label} SHA-256")


def _check_sbom_object(value, label):
    _check_object(value, label, {"filename", "sha256", "size", "kind"})
    _safe_relative(value["filename"], f"{label} filename", basename_only=True)
    _check_hash(value["sha256"], f"{label} SHA-256")
    _check_positive_int(value["size"], f"{label} size")
    if value["kind"] not in ("go-cyclonedx", "installed-files"):
        fail(f"{label} kind is not supported")


def _package_kind(name):
    if name == DAEMON_NAME:
        return "daemon"
    if name == UI_NAME:
        return "ui"
    fail(f"unsupported package name: {name}")


def _expected_sbom_kind(kind):
    return "go-cyclonedx" if kind == "daemon" else "installed-files"


def _validate_target(name, target, slug):
    if name == UI_NAME:
        if (target, slug) != UI_TARGET:
            fail(f"{UI_NAME} must use target all and slug noarch")
        return
    if EXPECTED_TARGETS.get(target) != slug:
        fail("target and slug do not match the supported build target set")


def _validate_dependency(package_version, depends, label):
    exact_forms = (
        re.compile(r"^serpent-wrt=" + re.escape(package_version) + r"$"),
        re.compile(
            r"^serpent-wrt\s*\(\s*=\s*"
            + re.escape(package_version)
            + r"\s*\)$"
        ),
    )
    if not any(
        isinstance(item, str)
        and any(pattern.fullmatch(item) for pattern in exact_forms)
        for item in depends
    ):
        fail(
            f"{label} must depend on serpent-wrt at the same APK version"
        )


# ---------------------------------------------------------------------------
# apk / openssl integration
# ---------------------------------------------------------------------------


def _apk_executable(sdk):
    sdk = os.fspath(sdk)
    if not os.path.isdir(sdk):
        fail("SDK is missing or is not a directory")
    apk = os.path.join(sdk, "staging_dir", "host", "bin", "apk")
    if not os.path.isfile(apk) or not os.access(apk, os.X_OK):
        fail("SDK host apk is missing or is not executable")
    return apk


def _validate_apk_options(apk):
    completed = _run(
        [apk, "--version"], label="apk --version", allow_failure=True
    )
    version_output = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    if completed.returncode != 0 or "apk-tools 3." not in version_output:
        fail("SDK host apk must be apk-tools 3.x")
    for subcommand, required in (
        ("adbsign", ("--sign-key",)),
        ("mkndx", ("--sign-key", "--output")),
    ):
        completed = _run(
            [apk, subcommand, "--help"],
            label=f"apk {subcommand} --help",
            allow_failure=True,
        )
        if completed.returncode not in (0, 1):
            fail(f"apk {subcommand} help inspection failed")
        text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
        for option in required:
            if option not in text:
                fail(f"apk {subcommand} does not advertise {option}")


def _adbdump(apk, path, label):
    completed = _run(
        [apk, "adbdump", "--format", "json", path], label=f"apk adbdump {label}"
    )
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"apk adbdump returned invalid JSON for {label}")
    if not isinstance(value, dict):
        fail(f"apk adbdump returned an unexpected structure for {label}")
    return value


def _package_info(apk, path, label):
    value = _adbdump(apk, path, label)
    info = value.get("info")
    if not isinstance(info, dict):
        fail(f"{label} has no APK metadata")
    for field in ("name", "version", "arch"):
        if not isinstance(info.get(field), str) or not info[field]:
            fail(f"{label} metadata is missing {field}")
    depends = info.get("depends", [])
    if not isinstance(depends, list) or not all(
        isinstance(item, str) for item in depends
    ):
        fail(f"{label} metadata has an invalid dependency list")
    return {"name": info["name"], "version": info["version"], "arch": info["arch"], "depends": depends}


def _verify_index_trust(apk, keys_dir, path, label, work_dir):
    """Require the index to verify with the candidate key and fail without it.

    Package-level ``apk verify`` is not used as a trust gate.  The signed
    index is the repository trust boundary that the target package manager
    consumes; a key-accept plus no-key-reject pair proves that this exact
    index requires the published key.
    """
    accepted = _run(
        [apk, "verify", "--keys-dir", keys_dir, path],
        label=f"apk verify {label}",
        allow_failure=True,
    )
    if accepted.returncode != 0:
        detail = accepted.stderr.decode("utf-8", "replace").strip()
        last = detail.splitlines()[-1] if detail else "verification failed"
        fail(f"{label} is not trusted by the candidate key: {last}")
    empty_keys = os.path.join(work_dir, "empty-keys")
    os.makedirs(empty_keys, mode=0o700, exist_ok=True)
    rejected = _run(
        [apk, "verify", "--keys-dir", empty_keys, path],
        label=f"apk verify {label} without the candidate key",
        allow_failure=True,
    )
    rejected_text = (rejected.stdout + rejected.stderr).decode(
        "utf-8", "replace"
    ).upper()
    if rejected.returncode == 0 or "UNTRUSTED" not in rejected_text:
        fail(f"{label} does not require the candidate key")


def _require_openssl():
    executable = shutil.which("openssl")
    if not executable:
        fail("openssl is required to validate the signing key")
    return executable


def _validate_private_key(openssl, key_path):
    _require_regular(key_path, "APK signing key")
    parsed = _run(
        [openssl, "pkey", "-in", key_path, "-noout", "-passin", "pass:"],
        label="openssl private key parse",
        allow_failure=True,
    )
    if parsed.returncode != 0:
        fail("APK signing key must be an unencrypted private key")
    text = _run(
        [openssl, "pkey", "-in", key_path, "-noout", "-text"],
        label="openssl private key inspection",
    ).stdout.decode("utf-8", "replace")
    if "Private-Key: (256 bit)" not in text:
        fail("APK signing key must be ECDSA P-256")
    if "prime256v1" not in text and "NIST CURVE: P-256" not in text:
        fail("APK signing key must use the P-256 curve")


def _derive_public_key(openssl, key_path, destination):
    _run(
        [openssl, "pkey", "-in", key_path, "-pubout", "-out", destination],
        label="openssl public key derivation",
    )
    _validate_public_key(openssl, destination)
    os.chmod(destination, 0o644)
    return destination


def _validate_public_key(openssl, public_key_path):
    _require_regular(public_key_path, "APK public key")
    completed = _run(
        [openssl, "pkey", "-pubin", "-in", public_key_path, "-noout", "-text"],
        label="openssl public key inspection",
        allow_failure=True,
    )
    if completed.returncode != 0:
        fail("repository public key is not a valid public key")
    text = completed.stdout.decode("utf-8", "replace")
    if "prime256v1" not in text and "NIST CURVE: P-256" not in text:
        fail("repository public key must be ECDSA P-256")
    if "Private-Key" in text:
        fail("repository public key must not contain private key material")


# ---------------------------------------------------------------------------
# Build manifests
# ---------------------------------------------------------------------------


def _validate_sbom(path, label, kind=None):
    raw = _read_bytes(path, label, MAX_SBOM_BYTES)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(f"{label} is not valid JSON")
    if not isinstance(value, dict):
        fail(f"{label} must contain a CycloneDX object")
    if value.get("bomFormat") != "CycloneDX":
        fail(f"{label} is not a CycloneDX document")
    if not isinstance(value.get("specVersion"), str):
        fail(f"{label} is missing its CycloneDX specification version")
    components = value.get("components")
    if not isinstance(components, list):
        fail(f"{label} is missing its CycloneDX components")
    if kind == "installed-files":
        metadata = value.get("metadata")
        candidates = list(components)
        if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
            candidates.append(metadata["component"])
        for component in candidates:
            if not isinstance(component, dict):
                continue
            purl = component.get("purl")
            if isinstance(purl, str) and purl.startswith("pkg:golang/"):
                fail(f"{label} describes Go modules, not installed files")
    return raw


def _validate_build_manifest(data, base_dir, apk, verifier):
    _check_object(
        data,
        "build manifest",
        {
            "schema_version",
            "kind",
            "source",
            "revisions",
            "sdk",
            "packages_ref",
            "target",
            "slug",
            "package",
            "sbom",
        },
    )
    if data["schema_version"] != SCHEMA_VERSION:
        fail("unsupported build manifest schema version")
    if data["kind"] != "serpent-apk-build":
        fail("build manifest kind is not serpent-apk-build")
    _check_source(data["source"], "build manifest source")
    revisions = data["revisions"]
    _check_object(
        revisions,
        "build manifest revisions",
        {"helper_commit", "workflow_commit"},
    )
    for field in ("helper_commit", "workflow_commit"):
        if not isinstance(revisions[field], str) or not GIT_OBJECT.fullmatch(
            revisions[field]
        ):
            fail(f"build manifest {field} must be a Git object id")
    _check_sdk(data["sdk"], "build manifest SDK")
    if not isinstance(data["packages_ref"], str) or not GIT_OBJECT.fullmatch(
        data["packages_ref"]
    ):
        fail("build manifest packages_ref must be a Git object id")

    package = data["package"]
    _check_object(
        package,
        "build manifest package",
        {"name", "version", "arch", "filename", "sha256", "size", "depends", "kind"},
    )
    name = package["name"]
    kind = _package_kind(name)
    if package["kind"] != kind:
        fail("build manifest package kind does not match its name")
    if not isinstance(package["version"], str) or not SAFE_COMPONENT.fullmatch(
        package["version"]
    ):
        fail("build manifest package version is invalid")
    if not isinstance(package["arch"], str) or not SAFE_COMPONENT.fullmatch(
        package["arch"]
    ):
        fail("build manifest package architecture is invalid")
    if kind == "ui" and package["arch"] != "noarch":
        fail(f"{UI_NAME} must use the noarch architecture")
    if kind == "daemon" and package["arch"] == "noarch":
        fail(f"{DAEMON_NAME} must not use the noarch architecture")
    _validate_target(name, data["target"], data["slug"])
    _validate_apk_version(data["source"]["package_version"], package["version"])
    expected_name = f"{name}-{package['version']}.apk"
    _safe_relative(package["filename"], "build manifest package filename", basename_only=True)
    if package["filename"] != expected_name:
        fail("build manifest package filename is not canonical")
    _check_hash(package["sha256"], "build manifest package SHA-256")
    _check_positive_int(package["size"], "build manifest package size")
    if not isinstance(package["depends"], list) or not all(
        isinstance(item, str) for item in package["depends"]
    ):
        fail("build manifest package depends must be a list of strings")
    if kind == "ui":
        _validate_dependency(
            package["version"], package["depends"], "build manifest UI package"
        )

    sbom = data["sbom"]
    _check_sbom_object(sbom, "build manifest SBOM")
    if sbom["kind"] != _expected_sbom_kind(kind):
        fail("build manifest SBOM kind does not match the package kind")
    if name not in sbom["filename"]:
        fail("build manifest SBOM filename does not identify its package")

    apk_path = _join_contained(base_dir, package["filename"], "package file", basename_only=True)
    sbom_path = _join_contained(base_dir, sbom["filename"], "SBOM file", basename_only=True)
    _require_regular(apk_path, "package file")
    _require_regular(sbom_path, "SBOM file")

    if sha256_file(apk_path) != package["sha256"]:
        fail("package file hash does not match its build manifest")
    if os.path.getsize(apk_path) != package["size"]:
        fail("package file size does not match its build manifest")
    sbom_bytes = _validate_sbom(sbom_path, "package SBOM", sbom["kind"])
    if hashlib.sha256(sbom_bytes).hexdigest() != sbom["sha256"]:
        fail("package SBOM hash does not match its build manifest")
    if len(sbom_bytes) != sbom["size"]:
        fail("package SBOM size does not match its build manifest")

    info = verifier(apk_path, package["filename"])
    if (
        info["name"] != name
        or info["version"] != package["version"]
        or info["arch"] != package["arch"]
        or sorted(info["depends"]) != sorted(package["depends"])
    ):
        fail("package metadata does not match its build manifest")

    return {
        "manifest": data,
        "base_dir": base_dir,
        "apk_path": apk_path,
        "sbom_path": sbom_path,
        "sbom_bytes": sbom_bytes,
        "package": package,
        "kind": kind,
    }


def command_build_manifest(args):
    apk = _apk_executable(args.sdk)
    _parse_human_version(args.package_version)
    _check_hash(args.sdk_sha256, "sdk sha256")
    if not args.sdk_url.startswith("https://"):
        fail("sdk-url must be an HTTPS URL")
    for value, label in (
        (args.source_commit, "source commit"),
        (args.source_tree, "source tree"),
        (args.helper_commit, "helper commit"),
        (args.workflow_commit, "workflow commit"),
        (args.packages_ref, "packages ref"),
    ):
        if not isinstance(value, str) or not GIT_OBJECT.fullmatch(value):
            fail(f"{label} must be a Git object id")

    output = os.path.abspath(args.output)
    output_name = os.path.basename(output)
    if output_name != "manifest.json" and not output_name.endswith(".manifest.json"):
        fail("manifest output must be manifest.json or *.manifest.json")
    bundle_dir = os.path.dirname(output)
    _require_directory(bundle_dir, "manifest output directory")
    _check_no_symlinks(bundle_dir, "manifest bundle")
    package_dir = _check_no_symlinks(args.package_dir, "package directory")
    candidates = [
        name
        for name in sorted(os.listdir(package_dir))
        if name.endswith(".apk") and os.path.isfile(os.path.join(package_dir, name))
    ]
    if len(candidates) != 1:
        fail("package directory must contain exactly one canonical APK")
    apk_path = os.path.join(package_dir, candidates[0])
    _require_regular(apk_path, "package file")
    info = _package_info(apk, apk_path, "package")
    name = info["name"]
    kind = _package_kind(name)
    _validate_apk_version(args.package_version, info["version"])
    _validate_target(name, args.target, args.slug)
    if kind == "ui" and info["arch"] != "noarch":
        fail(f"{UI_NAME} must use the noarch architecture")
    if kind == "daemon" and info["arch"] == "noarch":
        fail(f"{DAEMON_NAME} must not use the noarch architecture")
    canonical = f"{name}-{info['version']}.apk"
    if candidates[0] != canonical:
        fail("package filename must be name-version.apk with no target suffix")
    if kind == "ui":
        _validate_dependency(info["version"], info["depends"], "UI package")

    source_apk_hash = sha256_file(apk_path)
    bundle_apk = os.path.join(bundle_dir, canonical)
    if os.path.realpath(bundle_apk) != os.path.realpath(apk_path):
        if _missing(bundle_apk):
            _copy_file(apk_path, bundle_apk)
        else:
            _require_regular(bundle_apk, "bundle package")
            if sha256_file(bundle_apk) != source_apk_hash:
                fail("manifest bundle already contains different package bytes")
        apk_path = bundle_apk
    if sha256_file(apk_path) != source_apk_hash:
        fail("bundle package bytes do not match the input package")

    sbom_source = _require_regular(args.sbom, "SBOM")
    sbom_name = os.path.basename(sbom_source)
    _safe_component(sbom_name, "SBOM filename")
    sbom_bytes = _validate_sbom(
        sbom_source, "SBOM", _expected_sbom_kind(kind)
    )
    if name not in sbom_name:
        fail("SBOM filename must identify its package")
    sbom_hash = hashlib.sha256(sbom_bytes).hexdigest()
    sbom_path = os.path.join(bundle_dir, sbom_name)
    if os.path.realpath(sbom_path) != os.path.realpath(sbom_source):
        if _missing(sbom_path):
            _copy_file(sbom_source, sbom_path)
        else:
            _require_regular(sbom_path, "bundle SBOM")
            if sha256_file(sbom_path) != sbom_hash:
                fail("manifest bundle already contains a different SBOM")
    if sha256_file(sbom_path) != sbom_hash:
        fail("bundle SBOM bytes do not match the input SBOM")
    if os.path.realpath(output) in (
        os.path.realpath(apk_path),
        os.path.realpath(sbom_path),
    ):
        fail("manifest output must not overwrite a package or SBOM")
    sbom = {
        "filename": sbom_name,
        "sha256": hashlib.sha256(sbom_bytes).hexdigest(),
        "size": len(sbom_bytes),
        "kind": _expected_sbom_kind(kind),
    }

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "serpent-apk-build",
        "source": {
            "commit": args.source_commit,
            "tree": args.source_tree,
            "package_version": args.package_version,
        },
        "revisions": {
            "helper_commit": args.helper_commit,
            "workflow_commit": args.workflow_commit,
        },
        "sdk": {"url": args.sdk_url, "sha256": args.sdk_sha256},
        "packages_ref": args.packages_ref,
        "target": args.target,
        "slug": args.slug,
        "package": {
            "name": name,
            "version": info["version"],
            "arch": info["arch"],
            "filename": canonical,
            "sha256": sha256_file(apk_path),
            "size": os.path.getsize(apk_path),
            "depends": info["depends"],
            "kind": kind,
        },
        "sbom": sbom,
    }

    if os.path.isdir(output):
        fail("manifest output must be a file")
    _write_json(output, manifest)
    sys.stdout.write(
        json.dumps(
            {
                "status": "ok",
                "manifest": os.path.basename(output),
                "package": manifest["package"]["filename"],
                "sha256": manifest["package"]["sha256"],
            },
            sort_keys=True,
        )
        + "\n"
    )
    return 0


# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------


def _discover_build_manifests(inputs, apk):
    inputs = _check_no_symlinks(inputs, "staging inputs")
    paths = []
    for current, directories, files in os.walk(inputs, followlinks=False):
        directories.sort()
        for filename in sorted(files):
            if filename == "manifest.json" or filename.endswith(".manifest.json"):
                paths.append(os.path.join(current, filename))
    if not paths:
        fail("staging inputs contain no build manifests")

    seen = set()
    builds = []
    for path in sorted(paths):
        real = os.path.realpath(path)
        if real in seen:
            fail("staging inputs contain duplicate build manifests")
        seen.add(real)
        data, _ = _read_json(path, "build manifest", MAX_MANIFEST_BYTES)
        base_dir = os.path.dirname(path)
        build = _validate_build_manifest(
            data,
            base_dir,
            apk,
            lambda apk_path, label: _package_info(apk, apk_path, label),
        )
        builds.append(build)

    daemon_by_target = {}
    ui_builds = []
    for build in builds:
        package = build["package"]
        if build["kind"] == "ui":
            ui_builds.append(build)
            continue
        target = build["manifest"]["target"]
        if target in daemon_by_target:
            fail(f"staging inputs contain duplicate target {target}")
        daemon_by_target[target] = build

    if set(daemon_by_target) != set(EXPECTED_TARGETS):
        missing = sorted(set(EXPECTED_TARGETS) - set(daemon_by_target))
        extra = sorted(set(daemon_by_target) - set(EXPECTED_TARGETS))
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unsupported " + ", ".join(extra))
        fail("staging inputs are not complete: " + "; ".join(detail))
    if len(ui_builds) > 1:
        fail("staging inputs contain more than one UI build")

    builds = [daemon_by_target[target] for target in sorted(daemon_by_target)]
    builds.extend(ui_builds)

    reference = builds[0]
    reference_source = reference["manifest"]["source"]
    reference_revisions = reference["manifest"]["revisions"]
    reference_ref = reference["manifest"]["packages_ref"]
    for build in builds[1:]:
        manifest = build["manifest"]
        if manifest["source"] != reference_source:
            fail("build manifests disagree about the source commit, tree, or version")
        if manifest["revisions"] != reference_revisions:
            fail("build manifests disagree about helper or workflow revisions")
        if manifest["packages_ref"] != reference_ref:
            fail("build manifests disagree about the packages feed pin")

    versions = {build["package"]["version"] for build in builds}
    if len(versions) != 1:
        fail("build manifests disagree about the APK package version")

    arches = {}
    for build in builds:
        if build["kind"] != "daemon":
            continue
        arch = build["package"]["arch"]
        if arch in arches:
            fail("two daemon targets report the same APK architecture")
        arches[arch] = build

    human = reference_source["package_version"]
    major = _major_version(human)
    ui_build = ui_builds[0] if ui_builds else None
    if major == 0 and ui_build is not None:
        fail("v0.x candidates must not contain the LuCI package")
    if major >= 1 and ui_build is None:
        fail("v1.0 and later candidates require the real LuCI package")

    return {
        "builds": builds,
        "daemon_by_target": daemon_by_target,
        "daemon_arches": sorted(arches),
        "ui": ui_build,
        "source": reference_source,
        "revisions": reference_revisions,
        "sdks": sorted(
            [
                {
                    "target": build["manifest"]["target"],
                    "url": build["manifest"]["sdk"]["url"],
                    "sha256": build["manifest"]["sdk"]["sha256"],
                }
                for build in builds
            ],
            key=lambda item: item["target"],
        ),
        "packages_ref": reference_ref,
        "apk_version": sorted(versions)[0],
    }


# ---------------------------------------------------------------------------
# Repository manifest and prior tree
# ---------------------------------------------------------------------------


def _validate_package_record(record, label):
    _check_object(
        record,
        label,
        {
            "name",
            "version",
            "arch",
            "channel",
            "path",
            "sha256",
            "size",
            "source",
            "revisions",
            "target",
            "slug",
            "sdk",
            "unsigned_input_sha256",
            "sbom",
            "provenance",
        },
    )
    name = record["name"]
    kind = _package_kind(name)
    if kind == "ui" and record["arch"] != "noarch":
        fail(f"{label} UI record must use noarch")
    if kind == "daemon" and record["arch"] == "noarch":
        fail(f"{label} daemon record must not use noarch")
    if not isinstance(record["version"], str) or not SAFE_COMPONENT.fullmatch(
        record["version"]
    ):
        fail(f"{label} version is invalid")
    if not isinstance(record["arch"], str) or not SAFE_COMPONENT.fullmatch(
        record["arch"]
    ):
        fail(f"{label} architecture is invalid")
    if record["channel"] not in CHANNELS:
        fail(f"{label} channel is invalid")
    _validate_target(name, record["target"], record["slug"])
    _check_sdk(record["sdk"], f"{label} SDK")
    _check_hash(record["sha256"], f"{label} SHA-256")
    _check_positive_int(record["size"], f"{label} size")
    _check_hash(record["unsigned_input_sha256"], f"{label} unsigned input SHA-256")
    _check_source(record["source"], f"{label} source")
    _check_object(
        record["revisions"], f"{label} revisions", {"helper_commit", "workflow_commit"}
    )
    for field in ("helper_commit", "workflow_commit"):
        if not isinstance(record["revisions"][field], str) or not GIT_OBJECT.fullmatch(
            record["revisions"][field]
        ):
            fail(f"{label} {field} must be a Git object id")
    _validate_apk_version(record["source"]["package_version"], record["version"])
    _check_sbom_object(record["sbom"], f"{label} SBOM")
    if record["sbom"]["kind"] != _expected_sbom_kind(kind):
        fail(f"{label} SBOM kind does not match the package kind")
    if name not in record["sbom"]["filename"]:
        fail(f"{label} SBOM filename does not identify its package")
    if record["provenance"] not in ("new", "reused"):
        fail(f"{label} provenance is invalid")

    expected = (
        f"{REPOSITORY_ROOT}/{record['channel']}/{record['arch']}/{name}-{record['version']}.apk"
    )
    path = record["path"]
    _safe_relative(path, f"{label} path")
    parts = path.split("/")
    if len(parts) != 5 or parts[0] != "apk" or parts[1] != "25.12":
        fail(f"{label} path is not a repository package path")
    if parts[2] != record["channel"]:
        fail(f"{label} path channel does not match its record")
    if kind == "daemon" and parts[3] != record["arch"]:
        fail(f"{label} path architecture does not match its record")
    if kind == "ui" and parts[3] == "noarch":
        fail(f"{label} UI path must live beside a daemon architecture")
    if path != expected and kind == "daemon":
        fail(f"{label} path is not canonical")
    if os.path.basename(path) != f"{name}-{record['version']}.apk":
        fail(f"{label} filename is not canonical")


def _validate_index_record(record, label):
    _check_object(record, label, {"channel", "arch", "path", "sha256", "size"})
    if record["channel"] not in CHANNELS:
        fail(f"{label} channel is invalid")
    _safe_component(record["arch"], f"{label} architecture")
    _check_hash(record["sha256"], f"{label} SHA-256")
    _check_positive_int(record["size"], f"{label} size")
    expected = f"{REPOSITORY_ROOT}/{record['channel']}/{record['arch']}/packages.adb"
    if record["path"] != expected:
        fail(f"{label} path is not canonical")


def _validate_repository_manifest(data, pages_root, verify_hashes):
    _check_object(
        data,
        "repository manifest",
        {
            "schema_version",
            "kind",
            "source",
            "trust",
            "packages",
            "indexes",
            "previous_manifest_sha256",
        },
    )
    if data["schema_version"] != SCHEMA_VERSION:
        fail("unsupported repository manifest schema version")
    if data["kind"] != "serpent-apk-repository":
        fail("repository manifest kind is not serpent-apk-repository")
    _check_object(data["source"], "repository manifest source", {"commit", "tree", "package_version", "channel"})
    _check_source(
        {
            "commit": data["source"]["commit"],
            "tree": data["source"]["tree"],
            "package_version": data["source"]["package_version"],
        },
        "repository manifest source",
    )
    if data["source"]["channel"] not in CHANNELS:
        fail("repository manifest channel is invalid")
    _check_object(data["trust"], "repository manifest trust", {"public_key", "sha256"})
    if data["trust"]["public_key"] != PUBLIC_KEY_NAME:
        fail("repository manifest trust key name is invalid")
    _check_hash(data["trust"]["sha256"], "repository manifest trust SHA-256")
    if data["previous_manifest_sha256"] is not None:
        _check_hash(
            data["previous_manifest_sha256"],
            "repository manifest previous digest",
        )

    packages = data["packages"]
    indexes = data["indexes"]
    if not isinstance(packages, list) or not isinstance(indexes, list):
        fail("repository manifest packages and indexes must be arrays")

    by_path = {}
    by_identity = {}
    for index, record in enumerate(packages):
        _validate_package_record(record, f"repository package {index}")
        path = record["path"]
        if path in by_path:
            fail("repository manifest contains duplicate package paths")
        by_path[path] = record
        identity = (record["name"], record["version"], record["arch"])
        previous = by_identity.get(identity)
        if previous is not None:
            if previous["sha256"] != record["sha256"]:
                fail("one package version has different bytes in the repository")
        else:
            by_identity[identity] = record

    index_by_path = {}
    for index, record in enumerate(indexes):
        _validate_index_record(record, f"repository index {index}")
        path = record["path"]
        if path in index_by_path:
            fail("repository manifest contains duplicate index paths")
        index_by_path[path] = record

    key_path = os.path.join(pages_root, PUBLIC_KEY_NAME)
    if sha256_file(_require_regular(key_path, "repository public key")) != data["trust"][
        "sha256"
    ]:
        fail("repository public key hash does not match the repository manifest")

    if verify_hashes:
        for path, record in by_path.items():
            full = _join_contained(pages_root, path, "repository package path")
            _require_regular(full, "repository package")
            if sha256_file(full) != record["sha256"]:
                fail("repository package hash does not match its manifest")
            if os.path.getsize(full) != record["size"]:
                fail("repository package size does not match its manifest")
        for path, record in index_by_path.items():
            full = _join_contained(pages_root, path, "repository index path")
            _require_regular(full, "repository index")
            if sha256_file(full) != record["sha256"]:
                fail("repository index hash does not match its manifest")
            if os.path.getsize(full) != record["size"]:
                fail("repository index size does not match its manifest")

    discovered_packages = set()
    discovered_indexes = set()
    for relative in _files_under(pages_root):
        if relative.endswith(".apk"):
            discovered_packages.add(relative)
        elif relative.endswith("/packages.adb") or relative == "packages.adb":
            discovered_indexes.add(relative)
    if discovered_packages != set(by_path):
        fail("repository manifest does not inventory every published package")
    if discovered_indexes != set(index_by_path):
        fail("repository manifest does not inventory every published index")

    for path in discovered_packages:
        parent = os.path.dirname(path)
        expected_index = f"{parent}/packages.adb"
        if expected_index not in index_by_path:
            fail("published package directory has no indexed repository")
    for path in discovered_indexes:
        parent = os.path.dirname(path)
        if not any(package_path.startswith(parent + "/") for package_path in discovered_packages):
            fail("published index has no packages")

    return {
        "manifest": data,
        "packages": by_path,
        "package_identities": by_identity,
        "indexes": index_by_path,
        "trust_sha256": data["trust"]["sha256"],
    }


def _load_previous(previous, openssl):
    previous = _check_no_symlinks(previous, "previous Pages tree")
    manifest_path = os.path.join(previous, "repository-manifest.json")
    data, raw = _read_json(
        manifest_path, "previous repository manifest", MAX_REPOSITORY_BYTES
    )
    parsed = _validate_repository_manifest(data, previous, verify_hashes=True)
    _validate_public_key(openssl, os.path.join(previous, PUBLIC_KEY_NAME))
    parsed["root"] = previous
    parsed["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
    return parsed


# ---------------------------------------------------------------------------
# Stage
# ---------------------------------------------------------------------------


def _check_output_target(output):
    output = os.path.abspath(output)
    parent = os.path.dirname(output)
    _require_directory(parent, "candidate output parent")
    if _missing(output):
        return output
    info = os.lstat(output)
    if stat.S_ISLNK(info.st_mode):
        fail("candidate output must not be a symbolic link")
    if not stat.S_ISDIR(info.st_mode):
        fail("candidate output must be a directory")
    if os.listdir(output):
        fail("candidate output must be absent or empty")
    return output


def _validate_stage_paths(args):
    sdk = os.fspath(args.sdk)
    if not os.path.isdir(sdk):
        fail("SDK is missing or is not a directory")
    inputs = _check_no_symlinks(args.inputs, "staging inputs")
    key = _require_regular(args.private_key, "APK signing key")
    output = _check_output_target(args.output)
    previous = None
    if args.previous:
        previous = _check_no_symlinks(args.previous, "previous Pages tree")
        if _missing(os.path.join(previous, "repository-manifest.json")):
            fail("previous Pages tree has no repository manifest")
    for label, path in (("staging inputs", inputs), ("previous Pages tree", previous), ("SDK", sdk)):
        if path and _contained(output, path):
            fail(f"candidate output must be outside the {label}")
        if path and _contained(path, output):
            fail(f"{label} must be outside the candidate output")
    for label, path in (
        ("staging inputs", inputs),
        ("previous Pages tree", previous),
        ("SDK", sdk),
        ("candidate output", output),
    ):
        if path and _contained(key, path):
            fail(f"APK signing key must be outside the {label}")
    return output, previous


def _sign_package(apk, key, source, work_dir, label, expected_sha256):
    # Canonical filenames repeat across architectures, so each package needs a
    # separate signing directory; one shared directory rejects the second target.
    destination_dir = os.path.join(
        work_dir, "sign", hashlib.sha256(os.fsencode(source)).hexdigest()[:16]
    )
    os.makedirs(destination_dir, exist_ok=True)
    destination = os.path.join(destination_dir, os.path.basename(source))
    if not _missing(destination):
        fail("duplicate package signing request")
    unsigned_size = os.path.getsize(source)
    _copy_file(source, destination)
    if sha256_file(destination) != expected_sha256:
        fail("package bytes changed after manifest validation")
    _run(
        [
            apk,
            "adbsign",
            "--allow-untrusted",
            "--sign-key",
            key,
            destination,
        ],
        label=f"apk adbsign {label}",
    )
    signed_size = os.path.getsize(destination)
    if signed_size < unsigned_size // 2:
        fail("apk adbsign truncated the package instead of signing it")
    return destination


def _index_package_set(apk, path):
    value = _adbdump(apk, path, "repository index")
    packages = value.get("packages")
    if not isinstance(packages, list):
        fail("repository index has no package list")
    result = {}
    for item in packages:
        if not isinstance(item, dict):
            fail("repository index contains an invalid package entry")
        for field in ("name", "version", "arch"):
            if not isinstance(item.get(field), str):
                fail("repository index package is missing metadata")
        _check_positive_int(item.get("file-size"), "repository index package size")
        identity = (item["name"], item["version"], item["arch"])
        if identity in result:
            fail("repository index contains duplicate package metadata")
        result[identity] = item
    return result


def _tree_packages_metadata(apk, tree):
    result = {}
    for name in sorted(os.listdir(tree)):
        if not name.endswith(".apk"):
            continue
        full = os.path.join(tree, name)
        if not os.path.isfile(full) or os.path.islink(full):
            fail("repository tree contains an invalid package file")
        info = _package_info(apk, full, "repository package")
        expected = f"{info['name']}-{info['version']}.apk"
        if name != expected:
            fail("repository package filename is not canonical")
        identity = (info["name"], info["version"], info["arch"])
        if identity in result.values():
            fail("repository tree contains duplicate package metadata")
        result[full] = identity
    return result


def _index_matches_tree(apk, keys_dir, tree, work_dir):
    index_path = os.path.join(tree, "packages.adb")
    if _missing(index_path):
        return False
    if set(_tree_packages_metadata(apk, tree).values()) != set(
        _index_package_set(apk, index_path)
    ):
        return False
    _verify_index_trust(apk, keys_dir, index_path, "repository index", work_dir)
    return True


def _write_index(apk, keys_dir, key, tree, work_dir):
    package_paths = sorted(
        os.path.join(tree, name)
        for name in os.listdir(tree)
        if name.endswith(".apk")
    )
    if not package_paths:
        fail("cannot create an index for an empty repository tree")
    temporary = os.path.join(tree, ".packages.adb.tmp")
    if not _missing(temporary):
        os.unlink(temporary)
    try:
        _run(
            [
                apk,
                "mkndx",
                "--allow-untrusted",
                "--sign-key",
                key,
                "--output",
                temporary,
            ]
            + package_paths,
            label="apk mkndx",
        )
        _verify_index_trust(
            apk, keys_dir, temporary, "repository index", work_dir
        )
        os.chmod(temporary, 0o644)
        os.replace(temporary, os.path.join(tree, "packages.adb"))
    finally:
        if not _missing(temporary):
            os.unlink(temporary)


def _build_repository_manifest(pages, source, channel, previous_sha, trust_sha,
                               prior_packages, prior_indexes, selected_records):
    records = dict(prior_packages)
    for path, record in selected_records.items():
        if path in records:
            if records[path]["sha256"] != record["sha256"]:
                fail("selected package collides with a previous package path")
        else:
            records[path] = record

    tree_roots = sorted(
        {
            os.path.dirname(path)
            for path in _files_under(pages)
            if path.endswith(".apk")
        }
    )
    index_records = dict(prior_indexes)
    for tree in tree_roots:
        relative = f"{tree}/packages.adb"
        full = os.path.join(pages, *tree.split("/"))
        index_path = os.path.join(full, "packages.adb")
        if not os.path.isfile(index_path):
            fail("repository tree has no index")
        index_records[relative] = {
            "channel": tree.split("/")[2],
            "arch": tree.split("/")[3],
            "path": relative,
            "sha256": sha256_file(index_path),
            "size": os.path.getsize(index_path),
        }

    expected_trees = {os.path.dirname(path) for path in records}
    if set(tree_roots) != expected_trees:
        fail("repository manifest package inventory is incomplete")
    if set(index_records) != {f"{tree}/packages.adb" for tree in tree_roots}:
        fail("repository manifest index inventory is incomplete")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "kind": "serpent-apk-repository",
        "source": {
            "commit": source["commit"],
            "tree": source["tree"],
            "package_version": source["package_version"],
            "channel": channel,
        },
        "trust": {"public_key": PUBLIC_KEY_NAME, "sha256": trust_sha},
        "packages": [records[path] for path in sorted(records)],
        "indexes": [index_records[path] for path in sorted(index_records)],
        "previous_manifest_sha256": previous_sha,
    }
    _write_json(os.path.join(pages, "repository-manifest.json"), manifest)
    return manifest


def _release_name(name, version, slug, extension):
    return f"{name}-{version}-{slug}{extension}"


def _write_checksums(candidate, pages, release):
    lines = []
    for relative in _files_under(pages):
        full = os.path.join(pages, *relative.split("/"))
        lines.append(f"{sha256_file(full)}  pages/{relative}")
    for relative in _files_under(release):
        full = os.path.join(release, *relative.split("/"))
        lines.append(f"{sha256_file(full)}  release/{relative}")
    checksum_dir = os.path.join(candidate, "checksums")
    os.makedirs(checksum_dir, exist_ok=True)
    _write_atomic(
        os.path.join(checksum_dir, "SHA256SUMS"),
        ("\n".join(sorted(lines)) + "\n").encode("utf-8"),
    )


def _write_release_sums(release):
    lines = []
    for relative in _files_under(release):
        if relative == "SHA256SUMS":
            continue
        full = os.path.join(release, *relative.split("/"))
        lines.append(f"{sha256_file(full)}  {relative}")
    _write_atomic(
        os.path.join(release, "SHA256SUMS"),
        ("\n".join(sorted(lines)) + "\n").encode("utf-8"),
    )


def _file_contains_private_key(path):
    with open(path, "rb") as handle:
        carry = b""
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                return False
            data = carry + chunk
            if any(pattern in data for pattern in PRIVATE_PATTERNS):
                return True
            carry = data[-64:]


def _scan_private_key_material(candidate):
    for relative in _files_under(candidate):
        if relative.endswith(".key"):
            fail("candidate contains a private key file")
        if relative.endswith(".pem") and relative != f"pages/{PUBLIC_KEY_NAME}":
            fail("candidate contains an unexpected PEM file")
        path = os.path.join(candidate, *relative.split("/"))
        if _file_contains_private_key(path):
            fail("candidate contains private key material")


def command_stage(args):
    if args.channel not in CHANNELS:
        fail("channel must be testing or stable")
    output, previous_root = _validate_stage_paths(args)
    apk = _apk_executable(args.sdk)
    _validate_apk_options(apk)
    openssl = _require_openssl()
    _validate_private_key(openssl, args.private_key)

    inputs = _discover_build_manifests(args.inputs, apk)
    source = inputs["source"]
    human = source["package_version"]
    if args.channel == "stable" and _is_prerelease(human):
        fail("stable staging requires a final version, not a prerelease")
    prior = _load_previous(previous_root, openssl) if previous_root else None

    work_dir = tempfile.mkdtemp(prefix="serpent-apk-stage-")
    candidate = None
    published = False
    try:
        candidate = tempfile.mkdtemp(
            prefix=f".{os.path.basename(output)}.tmp-",
            dir=os.path.dirname(output),
        )
        pages = os.path.join(candidate, "pages")
        release = os.path.join(candidate, "release")
        os.makedirs(pages)
        os.makedirs(release)

        keys_dir = os.path.join(work_dir, "keys")
        os.makedirs(keys_dir, mode=0o700)
        public_key = os.path.join(keys_dir, PUBLIC_KEY_NAME)
        _derive_public_key(openssl, args.private_key, public_key)
        trust_sha = sha256_file(public_key)

        if prior is not None:
            if prior["trust_sha256"] != trust_sha:
                fail("previous repository was published with a different trust key")
            _copy_tree(prior["root"], pages)
            previous_key = os.path.join(pages, PUBLIC_KEY_NAME)
            if sha256_file(previous_key) != trust_sha:
                fail("previous repository public key does not match its manifest")
            previous_manifest_sha = prior["manifest_sha256"]
        else:
            previous_manifest_sha = None
            _copy_file(public_key, os.path.join(pages, PUBLIC_KEY_NAME))
        fingerprint = f"{trust_sha}  {PUBLIC_KEY_NAME}\n"
        _write_atomic(
            os.path.join(pages, f"{PUBLIC_KEY_NAME}.sha256"),
            fingerprint.encode("utf-8"),
        )

        prior_packages = prior["packages"] if prior else {}
        prior_identities = prior["package_identities"] if prior else {}
        prior_indexes = prior["indexes"] if prior else {}
        prior_by_identity = {
            identity: record for identity, record in prior_identities.items()
        }

        selected_records = {}
        selected_entries = []
        touched_trees = set()

        for build in inputs["builds"]:
            package = build["package"]
            identity = (package["name"], package["version"], package["arch"])
            provenance = "new"
            package_source = {
                "commit": source["commit"],
                "tree": source["tree"],
                "package_version": human,
            }
            package_revisions = build["manifest"]["revisions"]
            prior_record = prior_by_identity.get(identity)
            if prior_record is not None:
                if prior_record["source"]["commit"] != source["commit"] or (
                    prior_record["source"]["tree"] != source["tree"]
                ):
                    fail(
                        "refusing to re-sign an existing package version from a different source"
                    )
                if prior_record["source"]["package_version"] != human:
                    fail(
                        "refusing to re-attest an existing package under a different source version"
                    )
                if (
                    prior_record["target"] != build["manifest"]["target"]
                    or prior_record["slug"] != build["manifest"]["slug"]
                    or prior_record["sdk"] != build["manifest"]["sdk"]
                ):
                    fail(
                        "refusing to re-attest an existing package with different target or SDK provenance"
                    )
                if prior_record["unsigned_input_sha256"] != package["sha256"]:
                    fail(
                        "refusing to re-sign an existing package version from different unsigned bytes"
                    )
                if prior_record["sbom"]["sha256"] != hashlib.sha256(
                    build["sbom_bytes"]
                ).hexdigest() or prior_record["sbom"]["kind"] != build["manifest"][
                    "sbom"
                ]["kind"]:
                    fail("existing package version has different SBOM provenance")
                signed_bytes = _join_contained(
                    prior["root"], prior_record["path"], "previous package"
                )
                signed_sha = prior_record["sha256"]
                signed_size = prior_record["size"]
                package_source = prior_record["source"]
                package_revisions = prior_record["revisions"]
                provenance = "reused"
            else:
                signed_bytes = _sign_package(
                    apk,
                    args.private_key,
                    build["apk_path"],
                    work_dir,
                    package["filename"],
                    package["sha256"],
                )
                signed_sha = sha256_file(signed_bytes)
                signed_size = os.path.getsize(signed_bytes)

            if build["kind"] == "daemon":
                tree_paths = [build["package"]["arch"]]
            else:
                tree_paths = list(inputs["daemon_arches"])
            canonical_paths = []
            for arch in tree_paths:
                relative = (
                    f"{REPOSITORY_ROOT}/{args.channel}/{arch}/{package['filename']}"
                )
                destination = os.path.join(pages, *relative.split("/"))
                if not _missing(destination):
                    if sha256_file(destination) != signed_sha:
                        fail(
                            "existing package version has different bytes in the repository"
                        )
                else:
                    _copy_file(signed_bytes, destination)
                if sha256_file(destination) != signed_sha:
                    fail("final package bytes changed during staging")
                tree = os.path.dirname(relative)
                touched_trees.add(tree)
                canonical_paths.append(
                    {
                        "channel": args.channel,
                        "path": f"pages/{relative}",
                        "sha256": signed_sha,
                        "size": signed_size,
                    }
                )
                record = {
                    "name": package["name"],
                    "version": package["version"],
                    "arch": package["arch"],
                    "channel": args.channel,
                    "path": relative,
                    "sha256": signed_sha,
                    "size": signed_size,
                    "source": package_source,
                    "revisions": package_revisions,
                    "target": build["manifest"]["target"],
                    "slug": build["manifest"]["slug"],
                    "sdk": build["manifest"]["sdk"],
                    "unsigned_input_sha256": package["sha256"],
                    "sbom": {
                        "filename": build["manifest"]["sbom"]["filename"],
                        "sha256": build["manifest"]["sbom"]["sha256"],
                        "size": build["manifest"]["sbom"]["size"],
                        "kind": build["manifest"]["sbom"]["kind"],
                    },
                    "provenance": provenance,
                }
                selected_records[relative] = record

            release_stem = _release_name(
                package["name"],
                package["version"],
                build["manifest"]["slug"],
                "",
            )
            release_apk = f"{release_stem}.apk"
            release_sbom = f"{release_stem}.cdx.json"
            if not _missing(os.path.join(release, release_apk)):
                fail("duplicate release asset name")
            _copy_file(signed_bytes, os.path.join(release, release_apk))
            _copy_file(build["sbom_path"], os.path.join(release, release_sbom))
            selected_entries.append(
                {
                    "name": package["name"],
                    "version": package["version"],
                    "arch": package["arch"],
                    "kind": build["kind"],
                    "target": build["manifest"]["target"],
                    "slug": build["manifest"]["slug"],
                    "sdk": build["manifest"]["sdk"],
                    "unsigned_input_sha256": package["sha256"],
                    "source": package_source,
                    "revisions": package_revisions,
                    "provenance": provenance,
                    "canonical_paths": sorted(
                        canonical_paths, key=lambda item: item["path"]
                    ),
                    "release": {
                        "path": f"release/{release_apk}",
                        "sha256": signed_sha,
                        "size": signed_size,
                    },
                    "sbom": {
                        "path": f"release/{release_sbom}",
                        "sha256": build["manifest"]["sbom"]["sha256"],
                        "size": build["manifest"]["sbom"]["size"],
                        "kind": build["manifest"]["sbom"]["kind"],
                    },
                }
            )

        for tree in sorted(touched_trees):
            full_tree = os.path.join(pages, *tree.split("/"))
            _tree_packages_metadata(apk, full_tree)
            if not _index_matches_tree(apk, keys_dir, full_tree, work_dir):
                _write_index(apk, keys_dir, args.private_key, full_tree, work_dir)

        repository = _build_repository_manifest(
            pages,
            source,
            args.channel,
            previous_manifest_sha,
            trust_sha,
            prior_packages,
            prior_indexes,
            selected_records,
        )
        _write_release_sums(release)

        published_files = []
        for relative in _files_under(pages):
            full = os.path.join(pages, *relative.split("/"))
            published_files.append(
                {
                    "path": f"pages/{relative}",
                    "sha256": sha256_file(full),
                    "size": os.path.getsize(full),
                }
            )
        release_assets = []
        for relative in _files_under(release):
            full = os.path.join(release, *relative.split("/"))
            release_assets.append(
                {
                    "path": f"release/{relative}",
                    "sha256": sha256_file(full),
                    "size": os.path.getsize(full),
                }
            )

        candidate_data = {
            "schema_version": SCHEMA_VERSION,
            "kind": "serpent-apk-candidate",
            "channel": args.channel,
            "apk_version": inputs["apk_version"],
            "source": {
                "commit": source["commit"],
                "tree": source["tree"],
                "package_version": human,
            },
            "revisions": inputs["revisions"],
            "sdks": inputs["sdks"],
            "packages_ref": inputs["packages_ref"],
            "prior": {
                "initial": previous_root is None,
                "manifest_sha256": previous_manifest_sha,
            },
            "trust": {
                "public_key": f"pages/{PUBLIC_KEY_NAME}",
                "sha256": trust_sha,
                "fingerprint_sha256": trust_sha,
            },
            "packages": sorted(
                selected_entries, key=lambda item: (item["name"], item["version"], item["arch"])
            ),
            "indexes": [
                {
                    "channel": record["channel"],
                    "arch": record["arch"],
                    "path": f"pages/{record['path']}",
                    "sha256": record["sha256"],
                    "size": record["size"],
                }
                for record in sorted(repository["indexes"], key=lambda item: item["path"])
            ],
            "published_files": published_files,
            "release_assets": release_assets,
            "checksums": {
                "pages": "checksums/SHA256SUMS",
                "release": "release/SHA256SUMS",
            },
        }
        _write_json(os.path.join(candidate, "candidate.json"), candidate_data)
        candidate_bytes = open(
            os.path.join(candidate, "candidate.json"), "rb"
        ).read()
        _write_atomic(
            os.path.join(candidate, "candidate.sha256"),
            f"{hashlib.sha256(candidate_bytes).hexdigest()}  candidate.json\n".encode(
                "utf-8"
            ),
        )
        _write_checksums(candidate, pages, release)
        os.chmod(candidate, 0o755)

        verification_dir = os.path.join(work_dir, "verify")
        os.makedirs(verification_dir, mode=0o700)
        _verify_candidate(candidate, apk, openssl, verification_dir)
        _scan_private_key_material(candidate)

        if not _missing(output):
            os.rmdir(output)
        os.rename(candidate, output)
        published = True
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        if candidate is not None and not published:
            shutil.rmtree(candidate, ignore_errors=True)

    sys.stdout.write(
        json.dumps(
            {
                "status": "ok",
                "candidate": output,
                "channel": args.channel,
                "package_version": human,
                "apk_version": inputs["apk_version"],
            },
            sort_keys=True,
        )
        + "\n"
    )
    return 0


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _parse_sha256_lines(raw, label, *, basenames):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"{label} is not valid UTF-8")
    result = {}
    for line in text.splitlines():
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        if not match:
            fail(f"{label} contains an invalid checksum line")
        digest, path = match.groups()
        _safe_relative(path, f"{label} path", basename_only=basenames)
        if path in result:
            fail(f"{label} contains a duplicate path")
        result[path] = digest
    return result


def _verify_candidate(root, apk, openssl, work_dir):
    root = _check_no_symlinks(root, "candidate")
    data, raw = _read_json(
        os.path.join(root, "candidate.json"), "candidate manifest", MAX_CANDIDATE_BYTES
    )
    _check_object(
        data,
        "candidate manifest",
        {
            "schema_version",
            "kind",
            "channel",
            "apk_version",
            "source",
            "revisions",
            "sdks",
            "packages_ref",
            "prior",
            "trust",
            "packages",
            "indexes",
            "published_files",
            "release_assets",
            "checksums",
        },
    )
    if data["schema_version"] != SCHEMA_VERSION:
        fail("unsupported candidate schema version")
    if data["kind"] != "serpent-apk-candidate":
        fail("candidate manifest kind is not serpent-apk-candidate")
    if data["channel"] not in CHANNELS:
        fail("candidate channel is invalid")
    _check_source(data["source"], "candidate source")
    human = data["source"]["package_version"]
    if data["channel"] == "stable" and _is_prerelease(human):
        fail("stable candidate must use a final version")
    _validate_apk_version(human, data["apk_version"])
    _check_object(
        data["revisions"], "candidate revisions", {"helper_commit", "workflow_commit"}
    )
    for field in ("helper_commit", "workflow_commit"):
        if not isinstance(data["revisions"][field], str) or not GIT_OBJECT.fullmatch(
            data["revisions"][field]
        ):
            fail(f"candidate {field} must be a Git object id")
    if not isinstance(data["sdks"], list) or not data["sdks"]:
        fail("candidate sdks must be a non-empty array")
    candidate_sdks = set()
    for item in data["sdks"]:
        _check_object(item, "candidate SDK pin", {"target", "url", "sha256"})
        _check_sdk(
            {"url": item["url"], "sha256": item["sha256"]},
            "candidate SDK pin",
        )
        if item["target"] not in set(EXPECTED_TARGETS) | {UI_TARGET[0]}:
            fail("candidate SDK pin target is invalid")
        identity = (item["target"], item["url"], item["sha256"])
        if identity in candidate_sdks:
            fail("candidate contains duplicate SDK pins")
        candidate_sdks.add(identity)
    if not isinstance(data["packages_ref"], str) or not GIT_OBJECT.fullmatch(
        data["packages_ref"]
    ):
        fail("candidate packages_ref must be a Git object id")
    _check_object(data["prior"], "candidate prior", {"initial", "manifest_sha256"})
    if not isinstance(data["prior"]["initial"], bool):
        fail("candidate prior initial flag is invalid")
    if data["prior"]["initial"]:
        if data["prior"]["manifest_sha256"] is not None:
            fail("initial candidate must not record a previous manifest digest")
    else:
        _check_hash(
            data["prior"]["manifest_sha256"], "candidate previous manifest digest"
        )
    _check_object(
        data["trust"],
        "candidate trust",
        {"public_key", "sha256", "fingerprint_sha256"},
    )
    if data["trust"]["public_key"] != f"pages/{PUBLIC_KEY_NAME}":
        fail("candidate trust key path is invalid")
    _check_hash(data["trust"]["sha256"], "candidate trust SHA-256")
    _check_hash(
        data["trust"]["fingerprint_sha256"], "candidate fingerprint SHA-256"
    )

    checksum_path = os.path.join(root, "candidate.sha256")
    expected_candidate = _parse_sha256_lines(
        _read_bytes(checksum_path, "candidate checksum", 1024), "candidate checksum", basenames=True
    )
    if expected_candidate != {
        "candidate.json": hashlib.sha256(raw).hexdigest()
    }:
        fail("candidate manifest checksum does not match")

    public_key_path = os.path.join(root, "pages", PUBLIC_KEY_NAME)
    if sha256_file(_require_regular(public_key_path, "candidate public key")) != data[
        "trust"
    ]["sha256"]:
        fail("candidate public key does not match its manifest")
    if data["trust"]["fingerprint_sha256"] != data["trust"]["sha256"]:
        fail("candidate public key fingerprint does not match")
    _validate_public_key(openssl, public_key_path)
    fingerprint_path = os.path.join(root, "pages", f"{PUBLIC_KEY_NAME}.sha256")
    fingerprint = _parse_sha256_lines(
        _read_bytes(fingerprint_path, "public key fingerprint", 1024),
        "public key fingerprint",
        basenames=True,
    )
    if fingerprint != {PUBLIC_KEY_NAME: data["trust"]["sha256"]}:
        fail("public key fingerprint file does not match")

    pages = os.path.join(root, "pages")
    release = os.path.join(root, "release")
    _require_directory(pages, "candidate pages tree")
    _require_directory(release, "candidate release tree")

    published_files = data["published_files"]
    release_assets = data["release_assets"]
    if not isinstance(published_files, list) or not isinstance(release_assets, list):
        fail("candidate file inventories must be arrays")

    def inventory(entries, base, label):
        if not isinstance(entries, list):
            fail(f"{label} must be an array")
        result = {}
        for entry in entries:
            _check_object(entry, label, {"path", "sha256", "size"})
            path = entry["path"]
            _safe_relative(path, f"{label} path")
            if path in result:
                fail(f"{label} contains a duplicate path")
            _check_hash(entry["sha256"], f"{label} SHA-256")
            _check_nonnegative_int(entry["size"], f"{label} size")
            full = _join_contained(root, path, f"{label} path")
            _require_regular(full, f"{label} file")
            if sha256_file(full) != entry["sha256"]:
                fail(f"{label} hash does not match the file")
            if os.path.getsize(full) != entry["size"]:
                fail(f"{label} size does not match the file")
            result[path] = entry
        return result

    published = inventory(published_files, pages, "candidate published files")
    assets = inventory(release_assets, release, "candidate release assets")
    expected_published = {f"pages/{relative}" for relative in _files_under(pages)}
    expected_release = {f"release/{relative}" for relative in _files_under(release)}
    if set(published) != expected_published:
        fail("candidate published file inventory is incomplete")
    if set(assets) != expected_release:
        fail("candidate release asset inventory is incomplete")

    checksums = data["checksums"]
    _check_object(
        checksums, "candidate checksums", {"pages", "release"}
    )
    if checksums["pages"] != "checksums/SHA256SUMS":
        fail("candidate pages checksum path is invalid")
    if checksums["release"] != "release/SHA256SUMS":
        fail("candidate release checksum path is invalid")
    pages_sums = _parse_sha256_lines(
        _read_bytes(
            os.path.join(root, "checksums", "SHA256SUMS"),
            "candidate checksums",
            4 * 1024 * 1024,
        ),
        "candidate checksums",
        basenames=False,
    )
    expected_pages_sums = {
        path: entry["sha256"] for path, entry in published.items()
    }
    expected_pages_sums.update(
        {path: entry["sha256"] for path, entry in assets.items()}
    )
    if pages_sums != expected_pages_sums:
        fail("candidate checksums do not match its file inventory")
    release_sums = _parse_sha256_lines(
        _read_bytes(
            os.path.join(release, "SHA256SUMS"), "release checksums", 4 * 1024 * 1024
        ),
        "release checksums",
        basenames=True,
    )
    expected_release_sums = {
        os.path.basename(path): entry["sha256"]
        for path, entry in assets.items()
        if os.path.basename(path) != "SHA256SUMS"
    }
    if release_sums != expected_release_sums:
        fail("release checksums do not match the release assets")

    repository_data, _ = _read_json(
        os.path.join(pages, "repository-manifest.json"),
        "repository manifest",
        MAX_REPOSITORY_BYTES,
    )
    repository = _validate_repository_manifest(
        repository_data, pages, verify_hashes=True
    )
    if repository["trust_sha256"] != data["trust"]["sha256"]:
        fail("repository manifest trust key does not match the candidate")
    repository_source = repository_data["source"]
    if (
        repository_source["commit"] != data["source"]["commit"]
        or repository_source["tree"] != data["source"]["tree"]
        or repository_source["package_version"] != human
        or repository_source["channel"] != data["channel"]
    ):
        fail("repository manifest source does not match the candidate")
    if repository_data["previous_manifest_sha256"] != data["prior"][
        "manifest_sha256"
    ]:
        fail("repository manifest previous digest does not match the candidate")
    if data["prior"]["initial"]:
        for record in repository["packages"].values():
            if (
                record["source"] != data["source"]
                or record["version"] != data["apk_version"]
                or record["revisions"] != data["revisions"]
            ):
                fail("initial candidate contains packages from prior history")

    keys_dir = os.path.join(work_dir, "keys")
    os.makedirs(keys_dir, mode=0o700, exist_ok=True)
    _copy_file(public_key_path, os.path.join(keys_dir, PUBLIC_KEY_NAME))

    for relative, record in sorted(repository["packages"].items()):
        full = _join_contained(pages, relative, "repository package")
        info = _package_info(apk, full, "repository package")
        if (
            info["name"] != record["name"]
            or info["version"] != record["version"]
            or info["arch"] != record["arch"]
        ):
            fail("repository package metadata does not match its manifest")

    package_entries = data["packages"]
    if not isinstance(package_entries, list) or not package_entries:
        fail("candidate has no selected packages")
    selected = {}
    used_release_paths = set()
    used_sbom_paths = set()
    for index, entry in enumerate(package_entries):
        _check_object(
            entry,
            f"candidate package {index}",
            {
                "name",
                "version",
                "arch",
                "kind",
                "target",
                "slug",
                "sdk",
                "unsigned_input_sha256",
                "source",
                "revisions",
                "provenance",
                "canonical_paths",
                "release",
                "sbom",
            },
        )
        name = entry["name"]
        kind = _package_kind(name)
        if entry["kind"] != kind:
            fail("candidate package kind does not match its name")
        _validate_target(name, entry["target"], entry["slug"])
        _check_sdk(entry["sdk"], "candidate package SDK")
        if not isinstance(entry["version"], str) or entry["version"] != data[
            "apk_version"
        ]:
            fail("candidate package version does not match the candidate")
        if not isinstance(entry["arch"], str) or not SAFE_COMPONENT.fullmatch(
            entry["arch"]
        ):
            fail("candidate package architecture is invalid")
        if kind == "ui" and entry["arch"] != "noarch":
            fail("candidate UI package must use noarch")
        if kind == "daemon" and entry["arch"] == "noarch":
            fail("candidate daemon package must not use noarch")
        _check_source(entry["source"], "candidate package source")
        if entry["source"] != data["source"]:
            fail("candidate package source does not match the candidate source")
        _check_object(
            entry["revisions"],
            "candidate package revisions",
            {"helper_commit", "workflow_commit"},
        )
        for field in ("helper_commit", "workflow_commit"):
            if not isinstance(entry["revisions"][field], str) or not GIT_OBJECT.fullmatch(
                entry["revisions"][field]
            ):
                fail(f"candidate package {field} must be a Git object id")
        _validate_apk_version(human, entry["version"])
        _check_hash(entry["unsigned_input_sha256"], "candidate package input SHA-256")
        if entry["provenance"] not in ("new", "reused"):
            fail("candidate package provenance is invalid")
        identity = (name, entry["version"], entry["arch"])
        if identity in selected:
            fail("candidate contains duplicate package identities")
        selected[identity] = entry

        canonical_paths = entry["canonical_paths"]
        if not isinstance(canonical_paths, list) or not canonical_paths:
            fail("candidate package has no canonical paths")
        canonical_hashes = set()
        canonical_arch_dirs = set()
        canonical_relative_paths = set()
        for canonical in canonical_paths:
            _check_object(
                canonical,
                "candidate canonical path",
                {"channel", "path", "sha256", "size"},
            )
            if canonical["channel"] != data["channel"]:
                fail("candidate package canonical channel does not match")
            path = canonical["path"]
            _safe_relative(path, "candidate canonical path")
            parts = path.split("/")
            if len(parts) != 6 or parts[0] != "pages" or parts[1] != "apk" or parts[2] != "25.12":
                fail("candidate canonical path is not a repository path")
            if parts[3] != data["channel"]:
                fail("candidate canonical path channel is invalid")
            arch_dir = parts[4]
            if kind == "daemon" and arch_dir != entry["arch"]:
                fail("candidate daemon canonical path architecture is invalid")
            if kind == "ui" and arch_dir == "noarch":
                fail("candidate UI canonical path must live beside a daemon")
            if parts[5] != f"{name}-{entry['version']}.apk":
                fail("candidate canonical filename is invalid")
            if path in canonical_relative_paths:
                fail("candidate package has duplicate canonical paths")
            canonical_relative_paths.add(path)
            full = _join_contained(root, path, "candidate canonical package")
            _require_regular(full, "candidate canonical package")
            _check_hash(canonical["sha256"], "candidate canonical SHA-256")
            _check_positive_int(canonical["size"], "candidate canonical size")
            if sha256_file(full) != canonical["sha256"]:
                fail("candidate canonical package hash does not match")
            if os.path.getsize(full) != canonical["size"]:
                fail("candidate canonical package size does not match")
            canonical_hashes.add(canonical["sha256"])
            canonical_arch_dirs.add(arch_dir)
            info = _package_info(apk, full, "candidate package")
            if (
                info["name"] != name
                or info["version"] != entry["version"]
                or info["arch"] != entry["arch"]
            ):
                fail("candidate package metadata does not match its manifest")
            if kind == "ui":
                _validate_dependency(
                    entry["version"], info["depends"], "candidate UI package"
                )

        if len(canonical_hashes) != 1:
            fail("candidate package copies do not have identical bytes")
        if kind == "daemon":
            if len(canonical_paths) != 1:
                fail("candidate daemon package must have one canonical path")
            if canonical_arch_dirs != {entry["arch"]}:
                fail("candidate daemon package is not in its metadata architecture")

        release_entry = entry["release"]
        _check_object(
            release_entry, "candidate release asset", {"path", "sha256", "size"}
        )
        _safe_relative(release_entry["path"], "candidate release path")
        expected_release = (
            f"release/{name}-{entry['version']}-{entry['slug']}.apk"
        )
        if release_entry["path"] != expected_release:
            fail("candidate release asset path is not canonical")
        if release_entry["path"] in used_release_paths:
            fail("candidate release assets are not unique")
        used_release_paths.add(release_entry["path"])
        if release_entry["path"] not in assets:
            fail("candidate release asset is not inventoried")
        if release_entry["sha256"] not in canonical_hashes:
            fail("candidate release asset does not match the signed package")
        if not release_entry["path"].endswith(".apk"):
            fail("candidate release asset is not an APK")

        sbom_entry = entry["sbom"]
        _check_object(
            sbom_entry,
            "candidate package SBOM",
            {"path", "sha256", "size", "kind"},
        )
        if sbom_entry["kind"] != _expected_sbom_kind(kind):
            fail("candidate package SBOM kind does not match the package")
        _safe_relative(sbom_entry["path"], "candidate SBOM path")
        expected_sbom_path = (
            f"release/{name}-{entry['version']}-{entry['slug']}.cdx.json"
        )
        if sbom_entry["path"] != expected_sbom_path:
            fail("candidate SBOM path is not canonical")
        if sbom_entry["path"] in used_sbom_paths:
            fail("candidate SBOM assets are not unique")
        used_sbom_paths.add(sbom_entry["path"])
        if sbom_entry["path"] not in assets:
            fail("candidate SBOM is not inventoried")
        sbom_full = _join_contained(root, sbom_entry["path"], "candidate SBOM")
        sbom_bytes = _read_bytes(sbom_full, "candidate SBOM", MAX_SBOM_BYTES)
        if hashlib.sha256(sbom_bytes).hexdigest() != sbom_entry["sha256"]:
            fail("candidate SBOM hash does not match")
        if len(sbom_bytes) != sbom_entry["size"]:
            fail("candidate SBOM size does not match")
        _validate_sbom(sbom_full, "candidate SBOM", sbom_entry["kind"])
        if name not in os.path.basename(sbom_entry["path"]):
            fail("candidate SBOM filename does not identify its package")

        record = repository["packages"].get(
            canonical_paths[0]["path"][len("pages/"):]
        )
        if record is None:
            fail("candidate package is missing from the repository manifest")
        for canonical in canonical_paths:
            record = repository["packages"].get(canonical["path"][len("pages/"):])
            if (
                record is None
                or record["sha256"] != canonical["sha256"]
                or record["size"] != canonical["size"]
                or record["name"] != name
                or record["version"] != entry["version"]
                or record["arch"] != entry["arch"]
                or record["target"] != entry["target"]
                or record["slug"] != entry["slug"]
                or record["sdk"] != entry["sdk"]
                or record["source"] != entry["source"]
                or record["revisions"] != entry["revisions"]
                or record["unsigned_input_sha256"]
                != entry["unsigned_input_sha256"]
                or record["sbom"]["sha256"] != sbom_entry["sha256"]
                or record["sbom"]["size"] != sbom_entry["size"]
                or record["sbom"]["kind"] != sbom_entry["kind"]
            ):
                fail("candidate package does not match the repository manifest")

    expected_sdks = {
        (
            entry["target"],
            entry["sdk"]["url"],
            entry["sdk"]["sha256"],
        )
        for entry in selected.values()
    }
    if candidate_sdks != expected_sdks:
        fail("candidate SDK pins do not match the selected packages")

    daemon_entries = [
        entry for entry in selected.values() if entry["kind"] == "daemon"
    ]
    if len(daemon_entries) != 3:
        fail("candidate must contain exactly three daemon target builds")
    targets = {}
    arches = set()
    for entry in daemon_entries:
        target = entry["target"]
        if target in targets:
            fail("candidate contains duplicate daemon targets")
        targets[target] = entry
        if entry["arch"] in arches:
            fail("candidate daemon architectures must be distinct")
        arches.add(entry["arch"])
    if set(targets) != set(EXPECTED_TARGETS):
        fail("candidate daemon target set is incomplete or unsupported")
    for target, expected_slug in EXPECTED_TARGETS.items():
        if targets[target]["slug"] != expected_slug:
            fail("candidate daemon target slug is invalid")

    major = _major_version(human)
    ui_entries = [entry for entry in selected.values() if entry["kind"] == "ui"]
    repository_has_ui = any(
        record["name"] == UI_NAME for record in repository["packages"].values()
    )
    if major == 0:
        if ui_entries:
            fail("v0.x candidates must not contain the LuCI package")
        if repository_has_ui:
            fail("v0.x repository must not publish the LuCI package")
    else:
        if len(ui_entries) != 1:
            fail("v1.0 and later candidates require the real LuCI package")
        ui_entry = ui_entries[0]
        if set(
            path["path"].split("/")[4] for path in ui_entry["canonical_paths"]
        ) != arches:
            fail("candidate UI package must be present beside every daemon architecture")
        if ui_entry["version"] != data["apk_version"]:
            fail("candidate UI version is not synchronized with the daemon")

    expected_release_assets = {"release/SHA256SUMS"}
    for entry in selected.values():
        expected_release_assets.add(entry["release"]["path"])
        expected_release_assets.add(entry["sbom"]["path"])
    if set(assets) != expected_release_assets:
        fail("candidate release assets contain files outside the selected packages")

    discovered_indexes = {
        relative for relative in _files_under(pages) if relative.endswith("/packages.adb")
    }
    if set(repository["indexes"]) != discovered_indexes:
        fail("repository index inventory is incomplete")
    index_entries = data["indexes"]
    if not isinstance(index_entries, list):
        fail("candidate indexes must be an array")
    candidate_index_paths = set()
    for entry in index_entries:
        _check_object(
            entry, "candidate index", {"channel", "arch", "path", "sha256", "size"}
        )
        _safe_relative(entry["path"], "candidate index path")
        if not entry["path"].startswith("pages/"):
            fail("candidate index path is invalid")
        relative = entry["path"][len("pages/"):]
        if relative in candidate_index_paths:
            fail("candidate contains duplicate index paths")
        candidate_index_paths.add(relative)
        if relative not in repository["indexes"]:
            fail("candidate index is not in the repository manifest")
        record = repository["indexes"][relative]
        if (
            entry["sha256"] != record["sha256"]
            or entry["size"] != record["size"]
            or entry["channel"] != record["channel"]
            or entry["arch"] != record["arch"]
        ):
            fail("candidate index does not match the repository manifest")
    if candidate_index_paths != discovered_indexes:
        fail("candidate index inventory is incomplete")

    for relative in sorted(discovered_indexes):
        index_path = os.path.join(pages, *relative.split("/"))
        _verify_index_trust(
            apk, keys_dir, index_path, "repository index", work_dir
        )
        index_packages = _index_package_set(apk, index_path)
        index_set = set(index_packages)
        tree = os.path.dirname(index_path)
        tree_metadata = _tree_packages_metadata(apk, tree)
        if set(tree_metadata.values()) != index_set:
            fail("repository index does not reference exactly its canonical packages")
        for identity in sorted(index_set):
            name, version, _arch = identity
            canonical = os.path.join(tree, f"{name}-{version}.apk")
            if not os.path.isfile(canonical) or os.path.islink(canonical):
                fail(
                    "repository index package does not resolve to a canonical filename"
                )
            if os.path.getsize(canonical) != index_packages[identity]["file-size"]:
                fail("repository index file-size does not match the canonical package")

    _scan_private_key_material(root)

    return {
        "status": "ok",
        "candidate_sha256": hashlib.sha256(raw).hexdigest(),
        "index_trust": "apk verify accepts with the candidate key and rejects without it",
        "package_trust": "signed bytes and SHA-256 recorded; install and upgrade trust is external verification F",
        "channel": data["channel"],
        "package_version": human,
        "apk_version": data["apk_version"],
        "prior_manifest_sha256": data["prior"]["manifest_sha256"],
        "packages": [
            {
                "name": entry["name"],
                "version": entry["version"],
                "arch": entry["arch"],
                "kind": entry["kind"],
                "provenance": entry["provenance"],
            }
            for entry in sorted(
                selected.values(),
                key=lambda item: (item["name"], item["version"], item["arch"]),
            )
        ],
        "release_assets": sorted(assets),
    }


def command_verify(args):
    apk = _apk_executable(args.sdk)
    _validate_apk_options(apk)
    openssl = _require_openssl()
    work_dir = tempfile.mkdtemp(prefix="serpent-apk-verify-")
    try:
        summary = _verify_candidate(args.root, apk, openssl, work_dir)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
    sys.stdout.write(json.dumps(summary, sort_keys=True) + "\n")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(
        description="Build, sign, stage, and verify the Serpent APK repository."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    manifest = subparsers.add_parser(
        "build-manifest", help="write a build manifest for one unsigned APK"
    )
    manifest.add_argument("--sdk", required=True)
    manifest.add_argument("--package-dir", required=True)
    manifest.add_argument("--output", required=True)
    manifest.add_argument("--source-commit", required=True)
    manifest.add_argument("--source-tree", required=True)
    manifest.add_argument("--helper-commit", required=True)
    manifest.add_argument("--workflow-commit", required=True)
    manifest.add_argument("--package-version", required=True)
    manifest.add_argument("--target", required=True)
    manifest.add_argument("--slug", required=True)
    manifest.add_argument("--sdk-url", required=True)
    manifest.add_argument("--sdk-sha256", required=True)
    manifest.add_argument("--packages-ref", required=True)
    manifest.add_argument("--sbom", required=True)
    manifest.set_defaults(handler=command_build_manifest)

    stage = subparsers.add_parser(
        "stage", help="sign and stage a complete candidate repository"
    )
    stage.add_argument("--sdk", required=True)
    stage.add_argument("--inputs", required=True)
    stage.add_argument("--output", required=True)
    stage.add_argument("--channel", required=True, choices=CHANNELS)
    stage.add_argument("--private-key", required=True)
    stage.add_argument("--previous")
    stage.set_defaults(handler=command_stage)

    verify = subparsers.add_parser(
        "verify", help="read-only verification of a candidate repository"
    )
    verify.add_argument("--sdk", required=True)
    verify.add_argument("--root", required=True)
    verify.set_defaults(handler=command_verify)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except RepositoryError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2
    except KeyboardInterrupt:
        sys.stderr.write("ERROR: interrupted\n")
        return 130
    except OSError as exc:
        sys.stderr.write(f"ERROR: filesystem operation failed: {exc.strerror or exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
