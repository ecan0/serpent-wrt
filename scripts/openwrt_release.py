#!/usr/bin/env python3
"""Validate release workflow inputs and immutable Release asset plans.

This module contains only standard-library code.  The workflow uses it to
reject ambiguous Release selection records, mismatched digests, and asset
conflicts before any GitHub Pages or Release mutation happens.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?$"
)
DIGEST_RE = re.compile(r"^(?:sha256:)?([0-9a-f]{64})$")
ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$")
SELECTION_KEYS = {
    "Serpent-Candidate-Run",
    "Serpent-Candidate-Digest",
    "Serpent-Channel",
}
SELECTION_PREFIXES = ("Serpent-Candidate-", "Serpent-Channel")


class ReleaseInputError(ValueError):
    """A release input failed validation before publication."""


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_digest(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ReleaseInputError(f"{label} must be a sha256 string")
    match = DIGEST_RE.fullmatch(value.strip())
    if not match:
        raise ReleaseInputError(
            f"{label} must be a SHA-256 digest (64 lowercase hex): {value!r}"
        )
    return f"sha256:{match.group(1)}"


def parse_version(value: str) -> dict[str, Any]:
    """Map a human semantic version to its OpenWrt APK package version."""
    match = SEMVER_RE.fullmatch(value)
    if not match:
        raise ReleaseInputError(
            "package_version must use semantic version syntax "
            f"(MAJOR.MINOR.PATCH[-PRERELEASE]): {value!r}"
        )
    base = ".".join(match.group(index) for index in (1, 2, 3))
    prerelease = match.group(4)
    if prerelease is None:
        apk_version = base
        final = True
    else:
        sequence = prerelease.rsplit(".", 1)[-1]
        number = sequence if sequence.isdigit() else "1"
        apk_version = f"{base}_pre{number}"
        final = False
    return {
        "package_version": value,
        "apk_version": apk_version,
        "final": final,
    }


def parse_selection(text: str) -> dict[str, Any]:
    """Parse the exact Release-body selection record.

    Other Release-body text is ignored.  A line that starts with one of the
    reserved key prefixes but is malformed, empty, duplicated, or unknown
    fails the promotion instead of being ignored.
    """
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        if line.startswith(SELECTION_PREFIXES):
            key, separator, value = line.partition(":")
            if not separator or key not in SELECTION_KEYS:
                raise ReleaseInputError(f"invalid selection line: {line!r}")
            if key in values:
                raise ReleaseInputError(f"duplicate selection line: {key}")
            value = value.strip()
            if not value:
                raise ReleaseInputError(f"empty selection value: {key}")
            values[key] = value

    missing = sorted(SELECTION_KEYS - values.keys())
    if missing:
        raise ReleaseInputError(
            "Release body is missing selection lines: " + ", ".join(missing)
        )

    run_id = values["Serpent-Candidate-Run"]
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ReleaseInputError(
            f"Serpent-Candidate-Run must be a positive numeric run id: {run_id!r}"
        )

    channel = values["Serpent-Channel"]
    if channel not in {"testing", "stable"}:
        raise ReleaseInputError(
            f"Serpent-Channel must be testing or stable: {channel!r}"
        )

    digest = values["Serpent-Candidate-Digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ReleaseInputError(
            "Serpent-Candidate-Digest must use sha256:<64 lowercase hex>: "
            f"{digest!r}"
        )

    return {
        "run_id": int(run_id),
        "digest": digest,
        "channel": channel,
    }


def _asset_entries(document: Any, label: str) -> list[dict[str, Any]]:
    if isinstance(document, dict):
        entries = document.get("assets")
    else:
        entries = document
    if not isinstance(entries, list):
        raise ReleaseInputError(f"{label} must contain an assets array")
    normalized: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReleaseInputError(f"{label} asset entries must be objects")
        name = entry.get("name")
        if not isinstance(name, str) or not ASSET_NAME_RE.fullmatch(name):
            raise ReleaseInputError(f"{label} has an unsafe asset name: {name!r}")
        digest_value = entry.get("sha256", entry.get("digest"))
        if digest_value is None:
            normalized.append({"name": name, "sha256": None})
            continue
        normalized.append(
            {
                "name": name,
                "sha256": normalize_digest(digest_value, f"{label} {name}"),
            }
        )
    return normalized


def plan_asset_upload(
    candidate_document: Any,
    existing_document: Any,
    directory: Path,
) -> dict[str, list[str]]:
    """Return exactly which verified candidate assets still need uploading.

    Identical existing assets are skipped.  A name collision with different
    bytes fails because GitHub Release assets are immutable in this workflow.
    """
    candidate_assets = _asset_entries(candidate_document, "candidate assets")
    existing_assets = _asset_entries(existing_document, "existing assets")

    if not candidate_assets:
        raise ReleaseInputError("candidate has no Release assets to select")
    if not directory.is_dir():
        raise ReleaseInputError(f"candidate asset directory is missing: {directory}")

    candidate_by_name: dict[str, str] = {}
    for entry in candidate_assets:
        name = entry["name"]
        if entry["sha256"] is None:
            raise ReleaseInputError(f"candidate asset has no digest: {name}")
        if name in candidate_by_name:
            raise ReleaseInputError(f"duplicate candidate asset: {name}")
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise ReleaseInputError(f"candidate asset is not a regular file: {name}")
        actual = f"sha256:{file_sha256(path)}"
        if actual != entry["sha256"]:
            raise ReleaseInputError(
                f"candidate asset digest mismatch for {name}: "
                f"declared {entry['sha256']}, found {actual}"
            )
        candidate_by_name[name] = entry["sha256"]

    existing_by_name: dict[str, str | None] = {}
    for entry in existing_assets:
        name = entry["name"]
        if name in existing_by_name:
            raise ReleaseInputError(f"duplicate existing Release asset: {name}")
        existing_by_name[name] = entry["sha256"]

    upload: list[str] = []
    skip: list[str] = []
    for name in sorted(candidate_by_name):
        if name not in existing_by_name:
            upload.append(name)
            continue
        existing_digest = existing_by_name[name]
        if existing_digest is None:
            raise ReleaseInputError(
                f"existing Release asset {name} has no digest; refusing to guess"
            )
        if existing_digest != candidate_by_name[name]:
            raise ReleaseInputError(
                f"existing Release asset {name} has different bytes: "
                f"existing {existing_digest}, candidate {candidate_by_name[name]}"
            )
        skip.append(name)

    return {"upload": upload, "skip": skip}


def verify_file(path: Path, expected: str) -> None:
    if not path.is_file() or path.is_symlink():
        raise ReleaseInputError(f"not a regular file: {path}")
    actual = f"sha256:{file_sha256(path)}"
    if actual != normalize_digest(expected, "expected digest"):
        raise ReleaseInputError(
            f"digest mismatch for {path.name}: expected {expected}, found {actual}"
        )


def verify_base(
    expected: str | None,
    current: Path | None,
    allow_missing: bool,
    current_digest: str | None = None,
) -> None:
    """Refuse a candidate whose prior Pages base is not the live base."""
    if current is not None and current_digest is not None:
        raise ReleaseInputError("provide either --current-file or --current-digest")
    if current is not None and not current.exists():
        current = None
    if current is not None:
        if not current.is_file() or current.is_symlink():
            raise ReleaseInputError(f"current Pages manifest is not a file: {current}")
        current_digest = file_sha256(current)
    if current_digest:
        current_digest = normalize_digest(current_digest, "live Pages manifest digest")
    if expected:
        normalized = normalize_digest(expected, "prior Pages manifest digest")
        if not current_digest:
            raise ReleaseInputError(
                "candidate expects an existing prior Pages manifest, but none exists"
            )
        if current_digest != normalized:
            raise ReleaseInputError(
                "stale candidate base: live Pages manifest differs from the "
                f"candidate base ({current_digest} != {normalized})"
            )
        return
    if not allow_missing:
        raise ReleaseInputError(
            "candidate records no prior Pages manifest; "
            "initial repository publication requires explicit authorization"
        )
    if current_digest or (current is not None and current.exists()):
        raise ReleaseInputError(
            "initial repository publication refused: live Pages manifest exists"
        )


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseInputError(f"cannot read {label} {path}: {error}") from error


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    version = subparsers.add_parser("version", help="validate and map a version")
    version.add_argument("--version", required=True)

    selection = subparsers.add_parser(
        "parse-selection", help="parse the Release selection record"
    )
    selection.add_argument("--body-file", required=True, type=Path)

    digest = subparsers.add_parser("digest", help="print a file sha256 digest")
    digest.add_argument("--path", required=True, type=Path)

    verify = subparsers.add_parser("verify-file", help="verify a file digest")
    verify.add_argument("--path", required=True, type=Path)
    verify.add_argument("--digest", required=True)

    plan = subparsers.add_parser(
        "plan-assets", help="plan immutable Release asset uploads"
    )
    plan.add_argument("--assets", required=True, type=Path)
    plan.add_argument("--existing", required=True, type=Path)
    plan.add_argument("--directory", required=True, type=Path)

    base = subparsers.add_parser(
        "verify-base", help="compare the live Pages manifest to the candidate base"
    )
    base.add_argument("--expected-digest", default="")
    base.add_argument("--current-file", type=Path)
    base.add_argument("--current-digest", default=None)
    base.add_argument("--allow-missing", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "version":
            result = parse_version(args.version)
        elif args.command == "parse-selection":
            try:
                text = args.body_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                raise ReleaseInputError(
                    f"cannot read Release body {args.body_file}: {error}"
                ) from error
            result = parse_selection(text)
        elif args.command == "digest":
            result = {"sha256": file_sha256(args.path)}
        elif args.command == "verify-file":
            verify_file(args.path, args.digest)
            result = {"verified": str(args.path)}
        elif args.command == "plan-assets":
            result = plan_asset_upload(
                _load_json(args.assets, "candidate assets"),
                _load_json(args.existing, "existing Release assets"),
                args.directory,
            )
        elif args.command == "verify-base":
            verify_base(
                args.expected_digest,
                args.current_file,
                args.allow_missing,
                args.current_digest,
            )
            result = {"verified": True}
        else:  # pragma: no cover - argparse enforces the choices
            raise ReleaseInputError(f"unknown command: {args.command}")
    except ReleaseInputError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
