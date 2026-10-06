"""End-to-end policy precedence, protection selection and resource budgets."""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from tests.functional.cli.conftest import CliRunner
from zipctl import ZIP_CRYPTO, ZipFile


def test_test_continues_after_unsupported_encrypted_member(
    cli: CliRunner, tmp_path: Path
) -> None:
    source = tmp_path / "source.zip"
    with ZipFile(source, "w", encryption=ZIP_CRYPTO) as archive:
        archive.setpassword(b"password")
        archive.writestr("unsupported", b"payload")
        archive.writestr("good", b"good", encryption=None)
    data = bytearray(source.read_bytes())
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, 8, 9)
    struct.pack_into("<H", data, central + 10, 9)
    source.write_bytes(data)
    result = cli("test", str(source), "--json", env={"ZIPCTL_PASSWORD": "password"})
    report = cast("dict[str, Any]", json.loads(result.stdout))  # pyright: ignore[reportExplicitAny]
    assert result.returncode == 1
    assert report["tested"] == 2
    assert report["members"][1]["status"] == "ok"


def test_cli_resource_override_and_scope(cli: CliRunner, tmp_path: Path) -> None:
    source = tmp_path / "source.zip"
    with ZipFile(source, "w") as archive:
        archive.writestr("file", b"payload")
    refused = cli("list", str(source), "--archive-max-entries", "0")
    assert refused.returncode == 1
    assert "resource limit" in refused.stderr
    accepted = cli("list", str(source), "--archive-max-entries", "none")
    assert accepted.returncode == 0
    assert "file" in accepted.stdout
    window = cli("list", str(source), "--archive-max-zstd-window-bytes", "3")
    assert window.returncode == 2
    assert "must be a power of two from 1 KiB to 2 GiB" in window.stderr


def test_negated_protection_rule_and_compression_alias(
    cli: CliRunner, tmp_path: Path
) -> None:
    (tmp_path / "a.txt").write_text("public")
    (tmp_path / "b.txt").write_text("private")
    spec = tmp_path / "spec.json"
    spec.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "match": "[!a].txt",
                        "method": "aes256",
                        "password": {"env": "SECRET"},
                    }
                ]
            }
        )
    )
    source = tmp_path / "source.zip"
    result = cli(
        "create",
        str(source),
        "-C",
        str(tmp_path),
        "a.txt",
        "b.txt",
        "-m",
        "deflate",
        "--encryption-spec",
        str(spec),
        env={"SECRET": "password"},
    )
    assert result.returncode == 0, result.stderr
    with ZipFile(source) as archive:
        assert not archive.getinfo("a.txt").is_encrypted
        assert archive.getinfo("b.txt").is_encrypted
        assert archive.read("b.txt", pwd=b"password") == b"private"
    sevenzip = shutil.which("7z") or shutil.which("7zz")
    if sevenzip:
        checked = subprocess.run(
            [sevenzip, "t", "-ppassword", str(source)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert checked.returncode == 0, checked.stdout + checked.stderr


@pytest.mark.parametrize("mutate", [False, True])
def test_payload_corruption_agrees_with_7zip(tmp_path: Path, mutate: bool) -> None:
    sevenzip = shutil.which("7z") or shutil.which("7zz")
    if not sevenzip:
        pytest.skip("7-Zip is not installed")
    source = tmp_path / "source.zip"
    with ZipFile(source, "w") as archive:
        archive.writestr("file.txt", b"payload")
    if mutate:
        data = bytearray(source.read_bytes())
        data[38] ^= 0x80
        source.write_bytes(data)
    checked = subprocess.run(
        [sevenzip, "t", str(source)], capture_output=True, timeout=30
    )
    with ZipFile(source) as archive:
        assert (archive.testzip() is None) == (checked.returncode == 0) == (not mutate)


def _zeros_archive(path: Path) -> None:
    with ZipFile(path, "w", compression=8) as archive:
        archive.writestr("zeros", b"0" * 5_000_000)


def test_max_ratio_overrides_the_default_ratio_limit(
    cli: CliRunner, tmp_path: Path
) -> None:
    source = tmp_path / "zeros.zip"
    _zeros_archive(source)
    refused = cli("extract", str(source), "-d", str(tmp_path / "a"))
    assert refused.returncode == 1
    assert "Nothing extracted" in refused.stdout
    allowed = cli(
        "extract", str(source), "-d", str(tmp_path / "b"), "--max-ratio", "none"
    )
    assert allowed.returncode == 0
    assert (tmp_path / "b" / "zeros").stat().st_size == 5_000_000


def test_max_ratio_keeps_the_ratio_rule_action(cli: CliRunner, tmp_path: Path) -> None:
    source = tmp_path / "zeros.zip"
    _zeros_archive(source)
    policy = (
        '{"on_violation": "warn", '
        '"max_compression_ratio": {"value": 50, "on_violation": "error"}}'
    )
    result = cli(
        "extract", str(source), "-d", str(tmp_path / "out"),
        "--policy-json", policy, "--max-ratio", "200",
    )  # fmt: skip
    assert result.returncode == 1
    assert not (tmp_path / "out" / "zeros").exists()


def test_max_ratio_rejects_garbage(cli: CliRunner, tmp_path: Path) -> None:
    source = tmp_path / "zeros.zip"
    _zeros_archive(source)
    result = cli("extract", str(source), "--max-ratio", "-3")
    assert result.returncode == 2
    assert "--max-ratio expects a positive number or 'none'" in result.stderr


def test_archive_budgets_accept_units(cli: CliRunner, tmp_path: Path) -> None:
    source = tmp_path / "zeros.zip"
    _zeros_archive(source)
    ok = cli("list", str(source), "--archive-max-metadata-bytes", "1KiB")
    assert ok.returncode == 0
    bad = cli("list", str(source), "--archive-max-entries", "lots")
    assert bad.returncode == 2
    assert "expected a non-negative integer, a size such as 64MiB" in bad.stderr
