#!/usr/bin/env python3
"""Fetch and validate an immutable snapshot of the published Pages repository.

The snapshot is data only.  This helper never executes downloaded files.  It
validates every path and digest before a signing stage can use the snapshot as
a previous repository base.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA = 1
MANIFEST_KIND = "serpent-apk-repository"
DEFAULT_MANIFEST = "repository-manifest.json"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class SnapshotError(RuntimeError):
    """The published repository snapshot cannot be trusted or fetched."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise SnapshotError(f"redirects are not allowed: {newurl}")


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect)


def _validate_base_url(value: str, allow_http: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ({"https"} | ({"http"} if allow_http else set())):
        raise SnapshotError(f"base URL must use https: {value!r}")
    if not parsed.netloc or parsed.username or parsed.password:
        raise SnapshotError(f"base URL has no valid host: {value!r}")
    if parsed.query or parsed.fragment:
        raise SnapshotError(f"base URL must not contain a query or fragment: {value!r}")
    path = parsed.path or "/"
    if not path.endswith("/"):
        path += "/"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _fetch(base_url: str, relative_path: str, timeout: float, limit: int) -> bytes:
    url = base_url + urllib.parse.quote(relative_path, safe="/._-+")
    request = urllib.request.Request(url, method="GET")
    try:
        with _opener().open(request, timeout=timeout) as response:
            if response.status != 200:
                raise SnapshotError(f"unexpected HTTP {response.status} for {url}")
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    declared = int(length)
                except ValueError as error:
                    raise SnapshotError(f"invalid Content-Length for {url}") from error
                if declared < 0 or declared > limit:
                    raise SnapshotError(f"download too large for {url}: {declared} bytes")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(min(1024 * 1024, limit - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise SnapshotError(f"download exceeded {limit} bytes for {url}")
                chunks.append(chunk)
            return b"".join(chunks)
    except urllib.error.HTTPError as error:
        raise SnapshotError(f"HTTP {error.code} for {url}") from error
    except urllib.error.URLError as error:
        raise SnapshotError(f"cannot fetch {url}: {error.reason}") from error


def _manifest_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _validate_path(value: object, manifest_name: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or "\\" in value:
        raise SnapshotError(f"unsafe manifest path: {value!r}")
    parts = value.split("/")
    for part in parts:
        if part in {"", ".", ".."}:
            raise SnapshotError(f"unsafe manifest path: {value!r}")
    if value == manifest_name:
        raise SnapshotError("the manifest must not list itself")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/+-]*", value):
        raise SnapshotError(f"unsupported manifest path characters: {value!r}")
    return value


def parse_manifest(raw: bytes, manifest_name: str) -> list[tuple[str, str]]:
    """Validate the APK repository manifest and list every published file.

    The schema is owned by scripts/apk-repository.py.  The manifest inventories
    every package and index; the trust key is named separately by its digest.
    """
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SnapshotError(f"invalid repository manifest JSON: {error}") from error
    if not isinstance(document, dict):
        raise SnapshotError("repository manifest must be a JSON object")
    if document.get("schema_version") != MANIFEST_SCHEMA:
        raise SnapshotError(
            "unsupported repository manifest schema: "
            f"{document.get('schema_version')!r}"
        )
    if document.get("kind") != MANIFEST_KIND:
        raise SnapshotError(
            f"unexpected repository manifest kind: {document.get('kind')!r}"
        )
    trust = document.get("trust")
    if not isinstance(trust, dict):
        raise SnapshotError("repository manifest trust must be an object")
    public_key = _validate_path(trust.get("public_key"), manifest_name)
    public_key_digest = trust.get("sha256")

    entries: list[tuple[str, str]] = []

    def add(path: object, digest: object, label: str) -> None:
        validated = _validate_path(path, manifest_name)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise SnapshotError(f"invalid sha256 for {label} {validated!r}")
        entries.append((validated, digest))

    add(public_key, public_key_digest, "public key")
    for field in ("packages", "indexes"):
        records = document.get(field)
        if not isinstance(records, list):
            raise SnapshotError(f"repository manifest {field} must be an array")
        for record in records:
            if not isinstance(record, dict):
                raise SnapshotError(
                    f"repository manifest {field} entries must be objects"
                )
            add(record.get("path"), record.get("sha256"), field)

    seen: set[str] = set()
    for path, _ in entries:
        if path in seen:
            raise SnapshotError(f"duplicate manifest path: {path!r}")
        seen.add(path)
    return entries


def probe(base_url: str, manifest_name: str, timeout: float) -> dict[str, Any]:
    """Return the manifest presence and digest; raise on any non-404 failure."""
    url = base_url + urllib.parse.quote(manifest_name, safe="/._-+")
    request = urllib.request.Request(url, method="GET")
    try:
        with _opener().open(request, timeout=timeout) as response:
            if response.status != 200:
                raise SnapshotError(f"unexpected HTTP {response.status} for {url}")
            raw = response.read(MAX_MANIFEST_BYTES + 1)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"present": False, "sha256": None}
        raise SnapshotError(f"HTTP {error.code} for {url}") from error
    except urllib.error.URLError as error:
        raise SnapshotError(f"cannot fetch {url}: {error.reason}") from error
    if len(raw) > MAX_MANIFEST_BYTES:
        raise SnapshotError(f"repository manifest is too large: {url}")
    parse_manifest(raw, manifest_name)
    return {"present": True, "sha256": _manifest_sha256(raw)}


def fetch(
    base_url: str,
    output: Path,
    manifest_name: str,
    timeout: float,
) -> int:
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise SnapshotError(f"snapshot output must be absent or empty: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.", dir=str(output.parent))
    )
    try:
        raw = _fetch(base_url, manifest_name, timeout, MAX_MANIFEST_BYTES)
        entries = parse_manifest(raw, manifest_name)
        total = 0
        for relative_path, expected in entries:
            data = _fetch(base_url, relative_path, timeout, MAX_FILE_BYTES)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise SnapshotError(
                    f"repository snapshot exceeds {MAX_TOTAL_BYTES} bytes"
                )
            actual = hashlib.sha256(data).hexdigest()
            if actual != expected:
                raise SnapshotError(
                    f"digest mismatch for {relative_path}: "
                    f"expected {expected}, found {actual}"
                )
            destination = temporary / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            os.chmod(destination, 0o644)
        (temporary / manifest_name).write_bytes(raw)
        os.chmod(temporary / manifest_name, 0o644)
        if output.exists():
            output.rmdir()
        os.replace(temporary, output)
        return len(entries)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--allow-http",
        action="store_true",
        help="permit http URLs (tests only; the workflow never sets this)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    fetch_parser = subparsers.add_parser("fetch", help="download and verify a snapshot")
    fetch_parser.add_argument("--output", required=True, type=Path)

    subparsers.add_parser("probe", help="print manifest presence and digest")
    subparsers.add_parser(
        "require-missing", help="fail unless the manifest is absent"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        base_url = _validate_base_url(args.base_url, args.allow_http)
        if args.command == "fetch":
            count = fetch(base_url, args.output, args.manifest, args.timeout)
            print(json.dumps({"files": count}, sort_keys=True))
        elif args.command == "probe":
            print(json.dumps(probe(base_url, args.manifest, args.timeout), sort_keys=True))
        elif args.command == "require-missing":
            state = probe(base_url, args.manifest, args.timeout)
            if state["present"]:
                raise SnapshotError(
                    "initial repository publication refused: published manifest exists"
                )
            print(json.dumps({"absent": True}, sort_keys=True))
        else:  # pragma: no cover - argparse enforces the choices
            raise SnapshotError(f"unknown command: {args.command}")
    except SnapshotError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
