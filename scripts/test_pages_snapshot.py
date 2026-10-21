#!/usr/bin/env python3
"""Behavior tests for the trusted Pages repository snapshot helper."""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pages_snapshot


class Server:
    def __init__(self, routes: dict[str, tuple[int, bytes, dict[str, str]]]) -> None:
        self.routes = routes
        handler = self._handler()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        routes = self.routes

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
                path = self.path.split("?", 1)[0]
                status, body, headers = routes.get(
                    path, (404, b"missing", {})
                )
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        return Handler

    def __enter__(self) -> "Server":  # noqa: PYI034
        self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join()

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}/"


SOURCE = {
    "commit": "1" * 40,
    "tree": "2" * 40,
    "package_version": "0.5.0",
    "channel": "testing",
}


def record(path: str, data: bytes) -> dict[str, object]:
    return {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def manifest(
    packages: list[tuple[str, bytes]],
    indexes: list[tuple[str, bytes]] | None = None,
    public_key: bytes = b"public key",
    trust_sha256: str | None = None,
) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "kind": "serpent-apk-repository",
            "source": SOURCE,
            "trust": {
                "public_key": "serpent-wrt.pem",
                "sha256": trust_sha256
                or hashlib.sha256(public_key).hexdigest(),
            },
            "packages": [record(path, data) for path, data in packages],
            "indexes": [
                record(path, data) for path, data in (indexes or [])
            ],
            "previous_manifest_sha256": None,
        },
        sort_keys=True,
    ).encode()


class SnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_fetches_and_verifies_every_listed_file(self) -> None:
        package = b"package"
        index = b"index"
        key = b"public key"
        raw = manifest(
            [("apk/25.12/testing/i386_pentium4/serpent-wrt-0.5.0-r1.apk", package)],
            [("apk/25.12/testing/i386_pentium4/packages.adb", index)],
            key,
        )
        routes = {
            "/repository-manifest.json": (200, raw, {}),
            "/apk/25.12/testing/i386_pentium4/serpent-wrt-0.5.0-r1.apk": (
                200, package, {}
            ),
            "/apk/25.12/testing/i386_pentium4/packages.adb": (200, index, {}),
            "/serpent-wrt.pem": (200, key, {}),
        }
        with Server(routes) as server:
            output = self.root / "snapshot"
            count = pages_snapshot.fetch(
                server.url, output, "repository-manifest.json", 5
            )
        self.assertEqual(count, 3)
        self.assertEqual((output / "serpent-wrt.pem").read_bytes(), key)
        self.assertEqual(
            (output / "repository-manifest.json").read_bytes(), raw
        )

    def test_digest_mismatch_leaves_no_snapshot(self) -> None:
        key = b"public key"
        raw = manifest(
            [("apk/25.12/testing/i386_pentium4/serpent-wrt-0.5.0-r1.apk", b"expected")]
        )
        routes = {
            "/repository-manifest.json": (200, raw, {}),
            "/serpent-wrt.pem": (200, key, {}),
            "/apk/25.12/testing/i386_pentium4/serpent-wrt-0.5.0-r1.apk": (
                200, b"tampered", {}
            ),
        }
        with Server(routes) as server:
            with self.assertRaisesRegex(
                pages_snapshot.SnapshotError, "digest mismatch"
            ):
                pages_snapshot.fetch(
                    server.url, self.root / "snapshot", "repository-manifest.json", 5
                )
        self.assertFalse((self.root / "snapshot").exists())

    def test_traversal_and_duplicate_paths_are_rejected(self) -> None:
        base = json.loads(manifest([]))
        cases = []
        for path in ("../escape", "/absolute", "repository-manifest.json"):
            document = json.loads(json.dumps(base))
            document["packages"] = [
                {"path": path, "sha256": "a" * 64, "size": 1}
            ]
            cases.append(document)
        duplicate = json.loads(json.dumps(base))
        duplicate["packages"] = [
            {"path": "apk/25.12/testing/x/pkg.apk", "sha256": "a" * 64, "size": 1},
            {"path": "apk/25.12/testing/x/pkg.apk", "sha256": "b" * 64, "size": 1},
        ]
        cases.append(duplicate)
        invalid_trust = json.loads(json.dumps(base))
        invalid_trust["trust"]["public_key"] = "../key"
        cases.append(invalid_trust)
        for document in cases:
            with self.subTest(document=document):
                raw = json.dumps(document).encode()
                routes = {"/repository-manifest.json": (200, raw, {})}
                with Server(routes) as server:
                    with self.assertRaises(pages_snapshot.SnapshotError):
                        pages_snapshot.fetch(
                            server.url,
                            self.root / "snapshot",
                            "repository-manifest.json",
                            5,
                        )

    def test_probe_distinguishes_absent_from_errors(self) -> None:
        with Server({}) as server:
            self.assertEqual(
                pages_snapshot.probe(
                    server.url, "repository-manifest.json", 5
                ),
                {"present": False, "sha256": None},
            )

        with Server({"/repository-manifest.json": (500, b"boom", {})}) as server:
            with self.assertRaisesRegex(pages_snapshot.SnapshotError, "HTTP 500"):
                pages_snapshot.probe(server.url, "repository-manifest.json", 5)

        with Server(
            {"/repository-manifest.json": (200, b"{not json", {})}
        ) as server:
            with self.assertRaisesRegex(pages_snapshot.SnapshotError, "invalid"):
                pages_snapshot.probe(server.url, "repository-manifest.json", 5)

    def test_redirect_is_rejected(self) -> None:
        routes = {
            "/repository-manifest.json": (
                302,
                b"",
                {"Location": "https://example.invalid/manifest.json"},
            )
        }
        with Server(routes) as server:
            with self.assertRaisesRegex(pages_snapshot.SnapshotError, "redirects"):
                pages_snapshot.probe(server.url, "repository-manifest.json", 5)

    def test_require_missing_rejects_present_manifest(self) -> None:
        raw = manifest([])
        with Server({"/repository-manifest.json": (200, raw, {})}) as server:
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                status = pages_snapshot.main(
                    [
                        "--allow-http",
                        "--base-url",
                        server.url,
                        "require-missing",
                    ]
                )
        self.assertEqual(status, 1)
        self.assertIn("published manifest exists", stderr.getvalue())

    def test_require_missing_accepts_absent_manifest(self) -> None:
        with Server({}) as server:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = pages_snapshot.main(
                    [
                        "--allow-http",
                        "--base-url",
                        server.url,
                        "require-missing",
                    ]
                )
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stdout.getvalue()), {"absent": True})

    def test_http_requires_explicit_opt_in(self) -> None:
        with self.assertRaisesRegex(pages_snapshot.SnapshotError, "https"):
            pages_snapshot._validate_base_url("http://127.0.0.1/", False)
        self.assertEqual(
            pages_snapshot._validate_base_url("http://127.0.0.1/", True),
            "http://127.0.0.1/",
        )
        self.assertEqual(
            pages_snapshot._validate_base_url("https://example.org/repo", False),
            "https://example.org/repo/",
        )


if __name__ == "__main__":
    unittest.main()
