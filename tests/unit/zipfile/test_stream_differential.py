"""Reproducible mixed streaming operations and bounded payload mutations."""

import io
import lzma
import os
import random
import zipfile
import zlib
from typing import cast

import pytest

from tests.unit.zipfile.archive_factory import archive_bytes
from zipctl import WZ_AES, ZIP_CRYPTO, ArchiveResourceLimitError, BadZipFile, ZipFile
from zipctl.compression.zstd import compression_entry
from zipctl.zipfile.file.ext import ZipExtFile

METHODS = [
    0,
    8,
    12,
    14,
    pytest.param(
        93,
        marks=pytest.mark.skipif(
            compression_entry is None, reason="zstandard backend is unavailable"
        ),
    ),
]


def test_readline_limit_after_peek() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("file", b"x" * 4096)
    with ZipFile(buffer) as archive, archive.open("file") as reader:
        stream = cast(ZipExtFile, cast(object, reader))
        stream.peek(4096)
        assert stream.readline(878) == b"x" * 878
        assert stream.tell() == 878


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("encryption", [None, WZ_AES, ZIP_CRYPTO])
@pytest.mark.parametrize("size", [0, 1, 15, 4095, 4096, 4097, 16000])
def test_seeded_stream_sequences(
    method: int, encryption: str | None, size: int
) -> None:
    seed = int(os.environ.get("ZIPCTL_STREAM_SEED", "20261002"))
    operations = int(os.environ.get("ZIPCTL_STREAM_OPERATIONS", "100"))
    assert 1 <= operations <= 10000, "operation budget must be between 1 and 10000"
    rng = random.Random(seed)
    payload = rng.randbytes(size)
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=method, encryption=encryption) as archive:
        archive.setpassword(b"password")
        archive.writestr("file", payload)
    with ZipFile(buffer) as archive, archive.open("file", pwd=b"password") as reader:
        stream = cast(ZipExtFile, cast(object, reader))
        oracle = io.BytesIO(payload)
        for index in range(operations):
            op = rng.choice(("read", "read1", "peek", "seek", "readline"))
            count = rng.randrange(8192)
            context = (seed, method, encryption, size, index, op)
            if op == "seek":
                offset, whence = rng.randrange(-1000, size + 1001), rng.randrange(3)
                position = max(0, min(size, offset + (0, oracle.tell(), size)[whence]))
                assert stream.seek(offset, whence) == oracle.seek(position), context
            elif op == "read":
                assert stream.read(count) == oracle.read(count), context
            elif op == "readline":
                assert stream.readline(count) == oracle.readline(count), context
            else:
                data = stream.peek(count) if op == "peek" else stream.read1(count)
                position = oracle.tell()
                assert data == oracle.read(len(data)), context
                if op == "peek":
                    oracle.seek(position)
                else:
                    assert len(data) <= count, context
                    assert data or count == 0 or position == size, context
            assert stream.tell() == oracle.tell(), context


@pytest.mark.parametrize("method", [0, 8, 12, 14])
def test_seeded_payload_mutations_agree_with_stdlib(method: int) -> None:
    original = archive_bytes(method)
    end = original.index(b"PK\x01\x02")
    # Never ask the oracle to allocate a forged dictionary.
    start = 47 if method == 14 else 38
    for offset in random.Random(42).sample(range(start, end), min(5, end - start)):
        data = bytearray(original)
        data[offset] ^= 0x80
        for implementation in (ZipFile, zipfile.ZipFile):
            try:
                with implementation(io.BytesIO(data)) as archive:
                    result = archive.read("file.txt")
            except (
                BadZipFile,
                zipfile.BadZipFile,
                OSError,
                EOFError,
                zlib.error,
                lzma.LZMAError,
                ArchiveResourceLimitError,
            ):
                continue
            assert result == b"payload"
