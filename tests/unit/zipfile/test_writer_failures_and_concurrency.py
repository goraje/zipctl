"""Short I/O, failure recovery and concurrent closing of archive writers."""

from __future__ import annotations

import io
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from typing_extensions import Buffer, override

from zipctl import WZ_AES, ZIP_CRYPTO, ZipFile, ZipFileExtra
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.io_wrappers import write_all


class ShortWriter(io.BytesIO):
    @override
    def write(self, data: Buffer, /) -> int:
        return super().write(bytes(data)[:3])


@pytest.mark.parametrize("encryption", [None, WZ_AES, ZIP_CRYPTO])
def test_short_writes_preserve_every_record(encryption: str | None) -> None:
    buffer = ShortWriter()
    with ZipFile(buffer, "w", encryption=encryption) as archive:
        archive.setpassword(b"password")
        archive.writestr("file.txt", b"payload" * 100)
        archive.mkdir("dir")
        archive.comment = b"archive comment"
    with ZipFile(buffer) as archive:
        assert archive.read("file.txt", pwd=b"password") == b"payload" * 100
        assert archive.comment == b"archive comment"
        assert archive.namelist() == ["file.txt", "dir/"]


def test_mkdir_rejects_active_writer_without_changing_archive() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        with archive.open("file.txt", "w") as writer:
            writer.write(b"before")
            with pytest.raises(ValueError, match="write handle"):
                archive.mkdir("dir")
            writer.write(b"after")
        archive.mkdir("dir")
    with ZipFile(buffer) as archive:
        assert archive.read("file.txt") == b"beforeafter"


@pytest.mark.parametrize("encryption", [None, ZIP_CRYPTO, WZ_AES])
def test_reused_aes_info_obeys_new_encryption(encryption: str | None) -> None:
    source = io.BytesIO()
    with ZipFile(source, "w", encryption=WZ_AES) as archive:
        archive.setpassword(b"old")
        archive.writestr("file.txt", b"payload")
    with ZipFile(source) as archive:
        info = archive.infolist()[0]
        data = archive.read(info, pwd=b"old")
    target = io.BytesIO()
    with ZipFile(target, "w") as archive:
        archive.writestr(
            info,
            data,
            encryption=encryption,
            password=b"new" if encryption else None,
            extra=ZipFileExtra(wz_aes_nbits=128),
        )
    with ZipFile(target) as archive:
        assert archive.read("file.txt", pwd=b"new") == data
        assert archive.infolist()[0].encryption_scheme == encryption


def test_concurrent_close_registers_member_once() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=8) as archive:
        writer = archive.open("file.txt", "w")
        writer.write(b"payload")
        ready = threading.Barrier(8)

        def close_writer(_index: int) -> None:
            ready.wait(timeout=5)
            writer.close()

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(close_writer, range(32)))
        assert archive.namelist() == ["file.txt"]
    with ZipFile(buffer) as archive:
        assert archive.read("file.txt") == b"payload"


def test_failed_payload_write_does_not_register_entry() -> None:
    class FailingWriter(io.BytesIO):
        fail: bool = False

        @override
        def write(self, data: Buffer, /) -> int:
            if self.fail:
                raise OSError("disk full")
            return super().write(data)

    buffer = FailingWriter()
    with ZipFile(buffer, "w") as archive:
        writer = archive.open("bad", "w")
        buffer.fail = True
        with pytest.raises(OSError, match="disk full"):
            writer.write(b"payload")
        buffer.fail = False
        with pytest.raises(OSError, match="disk full"):
            writer.close()
        assert archive.namelist() == []
        archive.writestr("good", b"survives")
    with ZipFile(buffer) as archive:
        assert archive.read("good") == b"survives"


def test_closed_archive_mkdir_raises_value_error() -> None:
    archive = ZipFile(io.BytesIO(), "w")
    archive.close()
    with pytest.raises(ValueError, match="closed"):
        archive.mkdir(ZipInfo("dir/"))


def test_concurrent_archive_close_is_idempotent() -> None:
    buffer = io.BytesIO()
    archive = ZipFile(buffer, "w")
    archive.writestr("file.txt", b"payload")
    ready = threading.Barrier(8)

    def close_archive(_index: int) -> None:
        ready.wait(timeout=5)
        archive.close()

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(close_archive, range(32)))
    with ZipFile(buffer) as archive:
        assert archive.read("file.txt") == b"payload"


@pytest.mark.parametrize("bits", [0, 129, 512])
def test_invalid_aes_key_size_fails_at_configuration(bits: int) -> None:
    with pytest.raises(ValueError, match="wz_aes_nbits"):
        ZipFileExtra(wz_aes_nbits=bits)


def test_failed_header_rewrite_can_recover_without_corrupting_previous_entries() -> (
    None
):
    class HeaderFailure(io.BytesIO):
        fail: bool = False

        @override
        def write(self, data: Buffer, /) -> int:
            if self.fail and bytes(data).startswith(b"PK\x03\x04"):
                raise OSError("header write failed")
            return super().write(data)

    buffer = HeaderFailure()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("before", b"before")
        writer = archive.open("bad", "w")
        writer.write(b"payload")
        buffer.fail = True
        with pytest.raises(OSError, match="header write failed"):
            writer.close()
        buffer.fail = False
        archive.writestr("after", b"after")
    with ZipFile(buffer) as archive:
        assert archive.namelist() == ["before", "after"]
        assert archive.read("before") == b"before"
        assert archive.read("after") == b"after"


@pytest.mark.parametrize("count", [0, -1, 100])
def test_invalid_write_counts_fail_instead_of_looping(count: int) -> None:
    class InvalidWriter(io.BytesIO):
        @override
        def write(self, data: Buffer, /) -> int:
            return count

    with pytest.raises(OSError, match="Stream"):
        write_all(InvalidWriter(), b"payload")
