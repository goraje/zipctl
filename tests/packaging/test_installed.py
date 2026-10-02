"""Public behavior exercised without pytest or an editable source installation."""

# The wheel check intentionally has no test-framework dependencies.
# ruff: noqa: PT009, PT027

from __future__ import annotations

import io
import os
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from pathlib import Path

import zipctl
from zipctl.compression.zstd import compression_entry


class InstalledWheelTests(unittest.TestCase):
    def test_public_exports(self) -> None:
        for name in zipctl.__all__:
            self.assertTrue(hasattr(zipctl, name), name)
        self.assertTrue(Path(zipctl.__file__).with_name("py.typed").is_file())

    def test_encrypted_codecs_and_limits(self) -> None:
        methods = [0, 8, 12, 14] + ([93] if compression_entry else [])
        for method in methods:
            for encryption in (None, zipctl.WZ_AES, zipctl.ZIP_CRYPTO):
                with self.subTest(method=method, encryption=encryption):
                    self.check_round_trip(method, encryption)

    def check_round_trip(self, method: int, encryption: str | None) -> None:
        buffer = io.BytesIO()
        payload = b"installed wheel\n" * 100
        with zipctl.ZipFile(
            buffer, "w", compression=method, encryption=encryption
        ) as zf:
            zf.setpassword(b"wheel-test-password")
            zf.writestr("café.txt", payload)
            self.assertEqual(zf.read("café.txt"), payload)
        with zipctl.ZipFile(buffer) as zf:
            self.assertEqual(zf.read("café.txt", pwd=b"wheel-test-password"), payload)
        with self.assertRaises(zipctl.ArchiveResourceLimitError):
            zipctl.ZipFile(buffer, limits=zipctl.ArchiveLimits(max_entries=0))

    def test_optional_backend(self) -> None:
        dependencies = os.environ.get("ZIPCTL_WHEEL_DEPENDENCIES")
        if dependencies is None:
            self.skipTest("dependency isolation is checked by check_wheel.py")
        expected = dependencies != "base" or sys.version_info >= (3, 14)
        self.assertEqual(compression_entry is not None, expected)
        if not expected:
            with self.assertRaisesRegex(RuntimeError, "missing.*zstd"):
                with zipctl.ZipFile(io.BytesIO(), "w", compression=93) as zf:
                    zf.writestr("file", b"payload")

    def test_console_entry_point(self) -> None:
        script = Path(sysconfig.get_path("scripts")) / (
            "zipctl.exe" if os.name == "nt" else "zipctl"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.txt"
            source.write_bytes(b"CLI round trip")
            archive = root / "archive.zip"
            for args in (
                ["--help"],
                ["create", str(archive), "-C", str(root), "input.txt"],
                ["test", str(archive)],
                ["extract", str(archive), "-d", str(root / "output")],
            ):
                completed = subprocess.run(
                    [str(script), *args], capture_output=True, text=True, timeout=30
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                (root / "output/input.txt").read_bytes(), source.read_bytes()
            )


if __name__ == "__main__":
    if not Path(zipctl.__file__).is_relative_to(Path(sys.prefix)):
        raise SystemExit("zipctl was not imported from the isolated environment")
    unittest.main()
