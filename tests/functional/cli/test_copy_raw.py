"""``encrypt``, ``decrypt`` and ``rewrite`` keep the compressed data when they can."""

from __future__ import annotations

import random
import struct
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import pytest

import zipctl
from tests.functional.cli.rewrite_support import PASSWORD, PW
from zipctl import ZipFile
from zipctl.cli import main
from zipctl.compression import registry

Run = Callable[..., tuple[int, str, str]]
_RANDOM = random.Random(11)
# Text on which level 9 and the default level give different compressed sizes.
DATA = b" ".join(
    bytes(_RANDOM.choices(b"abcdefghij", k=_RANDOM.randint(2, 30))) for _ in range(3000)
)


@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Run:
    monkeypatch.setenv("ZIPCTL_PASSWORD", PASSWORD)
    monkeypatch.setenv("ZIPCTL_OLD_PASSWORD", PASSWORD)

    def go(*argv: str) -> tuple[int, str, str]:
        code = main(list(argv))
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return go


@pytest.fixture
def source(workdir: Path) -> Path:
    """Level 9 deflate: recompressing at the default level would change the size."""
    path = workdir / "in.zip"
    with ZipFile(path, "w", compresslevel=9) as zf:
        zf.writestr("a.txt", DATA, compress_type=zipctl.ZIP_DEFLATED)
        zf.writestr("b.txt", DATA[:9000], compress_type=zipctl.ZIP_DEFLATED)
    return path


def sizes(path: Path) -> list[int]:
    with ZipFile(path) as zf:
        return [info.compress_size for info in zf.infolist()]


def test_the_compressed_size_survives_encrypting_and_decrypting(
    run: Run, workdir: Path, source: Path
) -> None:
    before = sizes(source)
    assert run("encrypt", str(source), str(workdir / "e.zip"))[0] == 0
    assert run("decrypt", str(workdir / "e.zip"), str(workdir / "d.zip"))[0] == 0
    assert sizes(workdir / "d.zip") == before
    # WinZip AES adds a 16-byte salt, 2 verification bytes and a 10-byte tag
    assert sizes(workdir / "e.zip") == [size + 28 for size in before]


def test_nothing_is_compressed_when_the_compression_stays(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_compressor(
        _compress_type: int, _compresslevel: int | None = None
    ) -> NoReturn:
        raise AssertionError("compressed again")

    monkeypatch.setattr(registry, "get_compressor", no_compressor)
    assert run("encrypt", str(source), str(workdir / "e.zip"))[0] == 0
    assert run("rewrite", str(workdir / "e.zip"), str(workdir / "r.zip"))[0] == 0
    assert run("decrypt", str(workdir / "r.zip"), str(workdir / "d.zip"))[0] == 0
    with ZipFile(workdir / "d.zip") as zf:
        assert zf.read("a.txt") == DATA


def test_asking_for_a_compression_compresses_again(
    run: Run, workdir: Path, source: Path
) -> None:
    code, _, stderr = run(
        "rewrite",
        str(source),
        str(workdir / "r.zip"),
        "--compression",
        "deflate",
        "--level",
        "1",
    )
    assert code == 0, stderr
    assert sizes(workdir / "r.zip") != sizes(source)


def corrupt(path: Path) -> None:
    """Change one byte inside the compressed data of the first member."""
    data = bytearray(path.read_bytes())
    name_size, extra_size = struct.unpack_from("<HH", data, 26)
    data[30 + name_size + extra_size + 40] ^= 1
    path.write_bytes(bytes(data))


def test_a_corrupt_member_cannot_be_encrypted_even_without_the_read_back(
    run: Run, workdir: Path, source: Path
) -> None:
    # AES 2 stores no CRC: this is the last moment the data can be checked
    corrupt(source)
    code, _, stderr = run("encrypt", str(source), str(workdir / "e.zip"), "--no-verify")
    assert code == 1
    assert "cannot copy a.txt" in stderr
    assert not (workdir / "e.zip").exists()


def test_a_corrupt_member_is_caught_before_it_is_copied_as_it_is(
    run: Run, workdir: Path, source: Path
) -> None:
    corrupt(source)
    code, _, stderr = run("rewrite", str(source), str(workdir / "r.zip"))
    assert code == 1
    assert "cannot copy a.txt" in stderr
    assert not (workdir / "r.zip").exists()


def test_a_zipcrypto_archive_can_be_moved_to_aes(run: Run, workdir: Path) -> None:
    path = workdir / "z.zip"
    with ZipFile(path, "w") as zf:
        zf.writestr(
            "a.txt",
            DATA,
            compress_type=zipctl.ZIP_DEFLATED,
            encryption=zipctl.ZIP_CRYPTO,
            password=PW,
        )
    code, _, stderr = run(
        "rewrite", str(path), str(workdir / "a.zip"), "--encryption", "aes256"
    )
    assert code == 0, stderr
    with ZipFile(workdir / "a.zip") as zf:
        assert zf.read("a.txt", PW) == DATA
