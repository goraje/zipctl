"""Live member reads, append metadata, integrity resets and archive failure recovery."""

from __future__ import annotations

import io
import struct
import threading
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast

import pytest
from typing_extensions import Buffer, override

import zipctl
from tests.unit.zipfile.archive_factory import archive_bytes
from zipctl import (
    WZ_AES,
    ZIP_CRYPTO,
    BadZipFile,
    ZipFile,
    ZipInfo,
)
from zipctl.zipfile.ext import ZipExtFile


@pytest.mark.parametrize("encryption", [None, WZ_AES, ZIP_CRYPTO])
def test_completed_member_is_readable_before_archive_close(
    encryption: str | None,
) -> None:
    with ZipFile(io.BytesIO(), "w", encryption=encryption) as archive:
        archive.setpassword(b"password")
        archive.writestr("file.txt", b"payload")
        assert archive.read("file.txt") == b"payload"


def test_unicode_extra_survives_append() -> None:
    info = ZipInfo("legacy.txt")
    body = struct.pack("<BL", 1, zlib.crc32(b"legacy.txt")) + b"actual.txt"
    info.extra = struct.pack("<HH", 0x7075, len(body)) + body
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr(info, b"payload")
    with ZipFile(buffer, "a") as archive:
        archive.writestr("new", b"new")
    with ZipFile(buffer) as archive:
        assert archive.read("actual.txt") == b"payload"
    with zipfile.ZipFile(buffer) as archive:
        assert archive.read(archive.infolist()[0]) == b"payload"


def test_aes_append_does_not_duplicate_extra_fields() -> None:
    buffer = io.BytesIO(archive_bytes(encryption=WZ_AES))
    for index in range(3):
        with ZipFile(buffer, "a") as archive:
            archive.writestr(str(index), b"new")
    with ZipFile(buffer) as archive:
        info = archive.getinfo("file.txt")
        assert len(info.extra) == 11
        assert archive.read(info, pwd=b"password") == b"payload"


def test_invalid_text_codec_does_not_create_member() -> None:
    with ZipFile(io.BytesIO(), "w") as archive:
        path = zipctl.Path(archive, "unwanted")
        with pytest.raises(LookupError, match="encoding"):
            path.open("w", encoding="not-a-real-codec")
        assert archive.namelist() == []


class FailingStream(io.BytesIO):
    failure: BaseException | None = None

    @override
    def write(self, data: Buffer, /) -> int:
        if self.failure is not None:
            failure, self.failure = self.failure, None
            raise failure
        return super().write(data)


@pytest.mark.parametrize("failure", [OSError("disk full"), KeyboardInterrupt()])
def test_failed_long_write_recovers_and_reopens(failure: BaseException) -> None:
    buffer = FailingStream()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("before", b"before")
        writer = archive.open("bad", "w")
        writer.write(b"x" * 100_000)
        buffer.failure = failure
        with pytest.raises(type(failure)):
            writer.write(b"y")
        archive.writestr("after", b"after")
    with ZipFile(buffer) as archive:
        assert archive.namelist() == ["before", "after"]
        assert archive.read("before") == b"before"
        assert archive.read("after") == b"after"


def test_nonseekable_failure_cannot_report_success() -> None:
    class Unseekable(FailingStream):
        @override
        def seek(self, offset: int, whence: int = 0) -> int:
            raise io.UnsupportedOperation("seek")

    buffer = Unseekable()
    archive = ZipFile(buffer, "w")
    writer = archive.open("bad", "w")
    writer.write(b"first")
    buffer.failure = OSError("disk full")
    with pytest.raises(OSError, match="disk full"):
        writer.write(b"second")
    with pytest.raises(ValueError, match="non-seekable"):
        archive.writestr("after", b"after")
    with pytest.raises(ValueError, match="non-seekable"):
        archive.close()
    assert archive.fp is None


@pytest.mark.parametrize("mode", ["wb", "", "wbb", "r+"])
def test_invalid_path_open_is_side_effect_free(mode: str) -> None:
    with ZipFile(io.BytesIO(), "w") as archive:
        path = zipctl.Path(archive, "unwanted")
        with pytest.raises(ValueError, match="mode|encoding"):
            path.open(mode, encoding="utf-8")  # type: ignore[call-overload]  # pyright: ignore[reportArgumentType]  # ty: ignore[invalid-argument-type]
        assert archive.namelist() == []


def test_integrity_after_seek_checks_skipped_bytes() -> None:
    data = bytearray(archive_bytes())
    data[38] ^= 1
    with ZipFile(io.BytesIO(data)) as archive:
        with archive.open("file.txt") as reader:
            stream = cast(ZipExtFile, cast(object, reader))
            stream.seek(1)
            with pytest.raises(BadZipFile, match="CRC"):
                stream.verify_integrity()


def test_aes_integrity_can_be_repeated_after_read() -> None:
    with ZipFile(io.BytesIO(archive_bytes(encryption=WZ_AES))) as archive:
        with archive.open("file.txt", pwd=b"password") as reader:
            stream = cast(ZipExtFile, cast(object, reader))
            assert stream.read() == b"payload"
            stream.verify_integrity()
            stream.verify_integrity()
            assert stream.read() == b""
            stream.seek(0)
            assert stream.read() == b"payload"


@pytest.mark.parametrize("strict", [True, False])
def test_epoch_timestamp_range(monkeypatch: pytest.MonkeyPatch, strict: bool) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "0")
    with ZipFile(io.BytesIO(), "w", strict_timestamps=strict) as archive:
        if strict:
            with pytest.raises(ValueError, match="timestamps"):
                archive.writestr("file", b"data")
        else:
            archive.writestr("file", b"data")
            assert archive.getinfo("file").date_time == (1980, 1, 1, 0, 0, 0)


def test_concurrent_reader_registration_and_archive_close(tmp_path: Path) -> None:
    source = tmp_path / "source.zip"
    source.write_bytes(archive_bytes())
    archive = ZipFile(source)
    raw = archive.fp
    ready = threading.Barrier(8)

    def read_or_close(index: int) -> None:
        ready.wait(timeout=5)
        if index == 0:
            archive.close()
        else:
            try:
                reader = archive.open("file.txt")
            except ValueError as exc:
                assert "closed" in str(exc)  # noqa: PT017  # either race outcome is valid
            else:
                with reader:
                    assert reader.read() == b"payload"

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(read_or_close, range(8)))
    assert raw is not None
    assert raw.closed
    assert archive._stream._users == 0


@pytest.mark.parametrize("encryption", [None, WZ_AES, ZIP_CRYPTO])
def test_unicode_live_read(encryption: str | None) -> None:
    with ZipFile(io.BytesIO(), "w", encryption=encryption) as archive:
        archive.setpassword(b"password")
        archive.writestr("café.txt", b"payload")
        assert archive.read("café.txt") == b"payload"


def test_archive_finalization_failure_is_reported() -> None:
    buffer = FailingStream()
    archive = ZipFile(buffer, "w")
    archive.writestr("file", b"payload")
    buffer.failure = OSError("disk full")
    with pytest.raises(OSError, match="disk full"):
        archive.close()
    assert archive.fp is None
