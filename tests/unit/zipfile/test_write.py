from __future__ import annotations

import io
import threading
from pathlib import Path
from typing import cast

import pytest

import zipctl
from zipctl.compression import ZIP_STORED
from zipctl.cryptography.base import BaseZipEncryptor
from zipctl.zipfile import write as write_mod
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.shared import MASK_USE_DATA_DESCRIPTOR, ZIP64_LIMIT
from zipctl.zipfile.write import EntryOwner, ZipWriteFile


class _FakeEncryptor:
    def __init__(self, header: bytes = b"hdr", flush_tail: bytes = b"tag") -> None:
        self._zinfo: ZipInfo | None = None
        self._header: bytes = header
        self._flush_tail: bytes = flush_tail

    def update_zipinfo(self, zipinfo: ZipInfo) -> None:
        self._zinfo = zipinfo

    def encryption_header(self) -> bytes:
        return self._header

    def encrypt(self, data: bytes) -> bytes:
        return data

    def flush(self) -> bytes:
        return self._flush_tail


class _FakeArchive:
    """An ``EntryOwner``: what ``ZipWriteFile`` reports to."""

    def __init__(self) -> None:
        self.fp: io.BytesIO = io.BytesIO()
        self.lock: threading.RLock = threading.RLock()
        self.end: int = 0
        self.written: list[ZipInfo] = []
        self.failed: list[ZipWriteFile] = []

    def entry_written(self, entry: ZipWriteFile, zinfo: ZipInfo, end: int) -> None:
        del entry
        self.written.append(zinfo)
        self.end = end

    def entry_failed(self, entry: ZipWriteFile) -> None:
        self.failed.append(entry)


def _make_parent() -> _FakeArchive:
    return _FakeArchive()


def _as_owner(parent: _FakeArchive) -> EntryOwner:
    return parent


def _as_encryptor(encryptor: _FakeEncryptor) -> BaseZipEncryptor:
    return cast(
        "BaseZipEncryptor",
        encryptor,  # pyright: ignore[reportInvalidCast]  # duck-typed stand-in
    )


def _make_zinfo(name: str) -> ZipInfo:
    zinfo = ZipInfo(name)
    zinfo.compress_type = ZIP_STORED
    zinfo.compress_level = None
    zinfo.CRC = 0
    zinfo.file_size = 0
    zinfo.compress_size = 0
    zinfo.flag_bits = 0
    zinfo.header_offset = 0
    return zinfo


class TestZipWriteFile:
    def test_encryption_header_counts_toward_compress_size(self) -> None:
        parent = _make_parent()
        zinfo = _make_zinfo("a.txt")

        zwf = ZipWriteFile(
            _as_owner(parent),
            zinfo,
            zip64=False,
            encryptor=_as_encryptor(_FakeEncryptor(header=b"abc")),
        )

        assert zwf._compress_size == 3
        zwf.close()

    def test_close_registers_entry_and_commits_state(self) -> None:
        parent = _make_parent()
        zinfo = _make_zinfo("b.txt")

        with ZipWriteFile(_as_owner(parent), zinfo, zip64=False) as zwf:
            zwf.write(b"hello")

        assert zwf._state == write_mod.WriteState.COMMITTED
        assert parent.written == [zinfo]
        assert parent.end == len(parent.fp.getvalue())

    def test_non_zip64_file_size_over_limit_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(write_mod, "ZIP64_LIMIT", 1)
        parent = _make_parent()
        zinfo = _make_zinfo("big.txt")

        zwf = ZipWriteFile(_as_owner(parent), zinfo, zip64=False)
        zwf.write(b"abcd")

        with pytest.raises(
            RuntimeError,
            match="File size unexpectedly exceeded ZIP64 limit",
        ):
            zwf.close()
        assert zwf._state.value == "failed"

    def test_non_zip64_compress_size_over_limit_raises(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(write_mod, "ZIP64_LIMIT", 10)
        parent = _make_parent()
        zinfo = _make_zinfo("big-compress.txt")

        zwf = ZipWriteFile(
            _as_owner(parent),
            zinfo,
            zip64=False,
            encryptor=_as_encryptor(_FakeEncryptor(header=b"", flush_tail=b"x" * 16)),
        )
        zwf.write(b"a")

        with pytest.raises(
            RuntimeError,
            match="Compressed size unexpectedly exceeded ZIP64 limit",
        ):
            zwf.close()

    @pytest.mark.parametrize("use_descriptor", [False, True])
    def test_close_writes_data_descriptor_only_when_flag_set(
        self, use_descriptor: bool
    ) -> None:
        parent = _make_parent()
        zinfo = _make_zinfo("dd.txt")
        if use_descriptor:
            zinfo.flag_bits |= MASK_USE_DATA_DESCRIPTOR

        with ZipWriteFile(_as_owner(parent), zinfo, zip64=False) as zwf:
            zwf.write(b"abc")

        assert (b"PK\x07\x08" in parent.fp.getvalue()) is use_descriptor

    def test_finalization_failure_marks_writer_failed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        parent = _make_parent()
        zinfo = _make_zinfo("failed.txt")
        zwf = ZipWriteFile(
            _as_owner(parent),
            zinfo,
            zip64=False,
            encryptor=_as_encryptor(_FakeEncryptor(flush_tail=b"x" * 20)),
        )
        monkeypatch.setattr(write_mod, "ZIP64_LIMIT", 1)
        with pytest.raises(RuntimeError):
            zwf.close()
        assert zwf._state == write_mod.WriteState.FAILED
        assert parent.written == []
        assert parent.failed == [zwf]


class TestWriterRecovery:
    def test_zipfile_usable_after_failed_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed write must not permanently lock the archive.

        Regression test: a failed entry must give up the writer slot,
        otherwise every subsequent read, write, or close on this ZipFile
        raises forever.
        """
        original_limit = ZIP64_LIMIT
        monkeypatch.setattr(write_mod, "ZIP64_LIMIT", 1)
        archive = tmp_path / "recover.zip"
        zf = zipctl.ZipFile(archive, "w")
        writer = zf.open("big.bin", "w")
        writer.write(b"abcd")
        with pytest.raises(RuntimeError, match="ZIP64 limit"):
            writer.close()

        assert zf._writer.current is None

        monkeypatch.setattr(write_mod, "ZIP64_LIMIT", original_limit)
        zf.writestr("small.txt", b"ok")
        zf.close()

        with zipctl.ZipFile(archive) as zf2:
            assert zf2.read("small.txt") == b"ok"


def test_a_write_handle_that_fails_to_build_finalises_quietly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import gc
    import sys

    unraisable: list[object] = []
    monkeypatch.setattr(sys, "unraisablehook", unraisable.append)
    with zipctl.ZipFile(io.BytesIO(), "w") as zf:
        with pytest.raises(ValueError, match=r"\S"):
            zf.writestr(
                "a.txt", b"x", compress_type=zipctl.ZIP_DEFLATED, compresslevel=99
            )
        zf.writestr("b.txt", b"still usable")
    gc.collect()
    assert unraisable == []


def test_mkdir_accepts_a_zipinfo_that_has_not_been_written_yet() -> None:
    info = ZipInfo("docs/", (2020, 5, 17, 8, 30, 10))
    info.external_attr = (0o40750 << 16) | 0x10
    info.comment = b"folder"
    buffer = io.BytesIO()
    with zipctl.ZipFile(buffer, "w") as zf:
        zf.mkdir(info)
    with zipctl.ZipFile(buffer) as zf:
        (entry,) = zf.infolist()
    assert entry.is_dir()
    assert (entry.file_size, entry.compress_size, entry.CRC) == (0, 0, 0)
    assert entry.date_time == (2020, 5, 17, 8, 30, 10)
    assert entry.external_attr >> 16 == 0o40750
    assert entry.comment == b"folder"
