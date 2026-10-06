"""Short I/O, failure recovery and concurrent closing of archive writers."""

from __future__ import annotations

import io
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from typing_extensions import Buffer, override

from tests.helpers import NonSeekableBytesIO
from zipctl import WZ_AES, ZIP_CRYPTO, BadZipFile, ZipFile, ZipFileExtra
from zipctl.exceptions import PasswordRequired
from zipctl.zipfile.file.write import ZipWriteFile
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
            ready.wait(timeout=5)  # a Barrier: raises BrokenBarrierError on timeout
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
        ready.wait(timeout=5)  # a Barrier: raises BrokenBarrierError on timeout
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


def test_archive_close_waits_for_a_member_that_is_finishing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finishing = threading.Event()
    release = threading.Event()
    original = ZipWriteFile._write_final_payload

    def slow_final_payload(self: ZipWriteFile) -> None:
        finishing.set()
        assert release.wait(timeout=5)
        original(self)

    monkeypatch.setattr(ZipWriteFile, "_write_final_payload", slow_final_payload)
    buffer = io.BytesIO()
    archive = ZipFile(buffer, "w")
    writer = archive.open("file.txt", "w")
    writer.write(b"payload")
    closer = threading.Thread(target=writer.close)
    closer.start()
    assert finishing.wait(timeout=5)
    archive_closed = threading.Event()

    def close_archive() -> None:
        archive.close()
        archive_closed.set()

    waiter = threading.Thread(target=close_archive)
    waiter.start()
    assert not archive_closed.wait(timeout=0.1)
    release.set()
    closer.join(timeout=5)
    waiter.join(timeout=5)
    assert archive_closed.is_set()
    with ZipFile(buffer) as reopened:
        assert reopened.read("file.txt") == b"payload"


def test_duplicate_names_are_refused_before_anything_is_written() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("a", b"1")
        size = buffer.tell()
        with pytest.raises(ValueError, match="Duplicate name"):
            archive.writestr("a", b"2")
        with pytest.raises(ValueError, match="Duplicate name"):
            archive.open("a", "w")
        assert buffer.tell() == size
    with ZipFile(buffer) as archive:
        assert archive.namelist() == ["a"]


def test_duplicate_names_in_an_archive_are_refused() -> None:
    import warnings
    import zipfile as stdlib_zipfile

    buffer = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with stdlib_zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a", b"1")
            archive.writestr("a", b"2")
    with pytest.raises(BadZipFile, match="Duplicate name: 'a'"):
        ZipFile(buffer)


def _archive_with_old_entry() -> io.BytesIO:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.writestr("old", b"old")
    return buffer


def test_a_dropped_write_handle_does_not_jam_an_appended_archive() -> None:
    buffer = _archive_with_old_entry()
    archive = ZipFile(buffer, "a")
    handle = archive.open("new", "w")
    handle.write(b"new")
    del handle  # never closed: finished when collected, as in CPython
    archive.close()
    with ZipFile(buffer) as reread:
        assert reread.read("old") == b"old"
        assert reread.read("new") == b"new"


def test_an_error_inside_the_archive_block_aborts_the_open_entry() -> None:
    buffer = _archive_with_old_entry()
    with pytest.raises(KeyError, match="original"), ZipFile(buffer, "a") as archive:  # noqa: PT012
        handle = archive.open("new", "w")
        handle.write(b"partial")
        raise KeyError("original")
    with ZipFile(buffer) as reread:
        assert reread.namelist() == ["old"]
        assert reread.testzip() is None


def test_a_refused_entry_does_not_ruin_an_unseekable_archive() -> None:
    stream = NonSeekableBytesIO()
    with ZipFile(stream, "w", encryption=WZ_AES) as archive:
        with pytest.raises(PasswordRequired):
            archive.writestr("secret", b"x")
        archive.writestr("plain", b"y", encryption=None)
    with ZipFile(io.BytesIO(stream.getvalue())) as reread:
        assert reread.read("plain") == b"y"


@pytest.mark.parametrize("encryption", [WZ_AES, ZIP_CRYPTO])
def test_a_str_password_is_a_type_error_for_every_method(encryption: str) -> None:
    with ZipFile(io.BytesIO(), "w") as archive, pytest.raises(TypeError, match="bytes"):
        archive.writestr("a", b"a", encryption=encryption, password="secret")  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("method", ["bogus", ""])
def test_an_unknown_encryption_method_is_refused_up_front(method: str) -> None:
    with pytest.raises(ValueError, match="Unknown encryption"):
        ZipFile(io.BytesIO(), "w", encryption=method)
    with ZipFile(io.BytesIO(), "w") as archive:
        with pytest.raises(ValueError, match="Unknown encryption"):
            archive.encryption = method
        with pytest.raises(ValueError, match="Unknown encryption"):
            archive.writestr("a", b"a", encryption=method)


@pytest.mark.parametrize("year", [1979, 2108])
def test_a_date_dos_cannot_hold_is_a_value_error(year: int) -> None:
    with ZipFile(io.BytesIO(), "w") as archive:
        info = ZipInfo("a")
        info.date_time = (year, 1, 1, 0, 0, 0)
        with pytest.raises(ValueError, match="timestamps"):
            archive.writestr(info, b"a")


def test_an_unknown_metadata_encoding_is_refused_on_open() -> None:
    with pytest.raises(LookupError):
        ZipFile(_archive_with_old_entry(), metadata_encoding="no-such-codec")


def test_concurrent_write_and_writestr_wait_for_each_other(tmp_path: Path) -> None:
    source = tmp_path / "big"
    source.write_bytes(b"x" * (8 << 20))
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive, ThreadPoolExecutor(2) as pool:
        big = pool.submit(archive.write, source, "big")
        small = [pool.submit(archive.writestr, f"s{i}", b"s") for i in range(50)]
        big.result()
        for future in small:
            future.result()
    with ZipFile(buffer) as reread:
        assert len(reread.namelist()) == 51
        assert reread.testzip() is None
