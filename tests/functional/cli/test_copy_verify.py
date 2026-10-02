"""The read-back check that decides whether the output may replace anything.

A subprocess cannot be made to write a bad archive, so these run the command
in-process and break the writer on purpose.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Literal, TypedDict

import pytest
from typing_extensions import Unpack, override

from tests.functional.cli.rewrite_support import (
    PASSWORD,
    PW,
    leftovers,
    make_source,
    snapshot,
)
from zipctl import ZipFile
from zipctl.cli import main
from zipctl.zipfile.file import EncryptionOverride, ZipFileExtra
from zipctl.zipfile.file.writer import ArchiveWriter
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.write import ZipWriteFile

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer

Run = Callable[..., tuple[int, str, str]]


class OpenToWriteOptions(TypedDict, total=False):
    """The keyword-only parameters of ``ArchiveWriter.open``."""

    force_zip64: bool
    encryption: EncryptionOverride
    password: bytes | None
    extra: ZipFileExtra | None
    raw: bool


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
    return make_source(workdir / "in.zip")


# ``encrypt`` copies the compressed data as it is; the data checks below need
# the data to go through the compressor, which ``--compression`` asks for.
RECOMPRESS = ("rewrite", "--compression", "deflate")


def drop_last_byte(monkeypatch: pytest.MonkeyPatch) -> None:
    original = ZipWriteFile.write

    def write(self: ZipWriteFile, data: ReadableBuffer, /) -> int:
        raw = bytes(data)
        return original(self, raw[:-1] if len(raw) > 1 else raw)

    monkeypatch.setattr(ZipWriteFile, "write", write)


def flip_last_byte(monkeypatch: pytest.MonkeyPatch) -> None:
    original = ZipWriteFile.write

    def write(self: ZipWriteFile, data: ReadableBuffer, /) -> int:
        raw = bytes(data)
        return original(self, raw[:-1] + bytes([raw[-1] ^ 1]) if raw else raw)

    monkeypatch.setattr(ZipWriteFile, "write", write)


def test_data_of_the_same_length_but_different_content_is_caught(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flip_last_byte(monkeypatch)
    code, _, stderr = run(*RECOMPRESS, str(source), str(workdir / "out.zip"))
    assert code == 1, stderr
    assert "docs/readme.txt: the data read back differs" in stderr
    assert not (workdir / "out.zip").exists()


def test_data_of_a_different_length_is_caught_even_if_the_checksum_agrees(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class NoChecksum:
        @staticmethod
        def crc32(_data: bytes, _value: int = 0) -> int:
            return 0

    monkeypatch.setattr("zipctl.cli.commands.helpers.copying.copy.zlib", NoChecksum)
    monkeypatch.setattr("zipctl.cli.commands.helpers.copying.verify.zlib", NoChecksum)
    drop_last_byte(monkeypatch)
    code, _, stderr = run(*RECOMPRESS, str(source), str(workdir / "out.zip"))
    assert code == 1, stderr
    assert "docs/readme.txt: the data read back differs" in stderr


def test_compressed_data_that_is_copied_wrongly_is_caught_too(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = ZipWriteFile.write_raw

    def write_raw(self: ZipWriteFile, data: bytes) -> None:
        original(self, data[:-1] + bytes([data[-1] ^ 1]))

    monkeypatch.setattr(ZipWriteFile, "write_raw", write_raw)
    out = workdir / "out.zip"
    code, _, stderr = run("encrypt", str(source), str(out))
    assert code == 1, stderr
    assert "verification of the new archive failed" in stderr
    assert not out.exists()


def test_compression_option_bits_that_are_not_carried_over_are_caught(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = ArchiveWriter.open

    def wrong_bits(
        self: ArchiveWriter, zinfo: ZipInfo, **kw: Unpack[OpenToWriteOptions]
    ) -> ZipWriteFile:
        zinfo.flag_bits ^= 0b010
        return original(self, zinfo, **kw)

    monkeypatch.setattr(ArchiveWriter, "open", wrong_bits)
    out = workdir / "out.zip"
    code, _, stderr = run("encrypt", str(source), str(out))
    assert code == 1
    assert "the compressed data was not copied as it was" in stderr
    assert not out.exists()


def test_data_that_does_not_read_back_the_same_stops_the_run(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drop_last_byte(monkeypatch)
    out = workdir / "out.zip"
    code, stdout, stderr = run(*RECOMPRESS, str(source), str(out))
    assert code == 1, stderr
    assert "verification of the new archive failed" in stderr
    assert "nothing was written" in stderr
    assert "docs/readme.txt: the data read back differs" in stderr
    assert stdout == ""
    assert not out.exists()
    assert leftovers(workdir) == []


def test_a_failed_check_leaves_an_existing_output_untouched(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drop_last_byte(monkeypatch)
    out = workdir / "out.zip"
    out.write_bytes(b"precious")
    code, _, _ = run(*RECOMPRESS, str(source), str(out), "--force")
    assert code == 1
    assert out.read_bytes() == b"precious"
    assert leftovers(workdir) == []


def test_without_the_check_the_bad_archive_is_moved_into_place(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drop_last_byte(monkeypatch)
    out = workdir / "out.zip"
    code, stdout, _ = run(*RECOMPRESS, str(source), str(out), "--no-verify")
    assert code == 0
    assert "verified" not in stdout
    assert out.exists()


def test_a_long_list_of_problems_is_cut_short(
    run: Run, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.functional.cli.support import write_archive

    write_archive(
        workdir / "many.zip", [(f"file{i:02}.txt", b"abcdef") for i in range(14)]
    )
    drop_last_byte(monkeypatch)
    code, _, stderr = run(
        *RECOMPRESS, str(workdir / "many.zip"), str(workdir / "o.zip")
    )
    assert code == 1
    assert stderr.count("differs") == 10
    assert "  and 4 more" in stderr


def test_a_member_written_with_the_wrong_protection_is_caught(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = ArchiveWriter.open

    def open_plain(
        self: ArchiveWriter, zinfo: ZipInfo, **kw: Unpack[OpenToWriteOptions]
    ) -> ZipWriteFile:
        kw["encryption"] = None
        kw["password"] = None
        return original(self, zinfo, **kw)

    monkeypatch.setattr(ArchiveWriter, "open", open_plain)
    out = workdir / "out.zip"
    code, _, stderr = run("encrypt", str(source), str(out))
    assert code == 1
    assert "is none, not AES-256" in stderr
    assert not out.exists()


def test_a_member_that_is_missing_from_the_output_is_caught(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:

    def skip_mkdir(
        _self: ZipFile, _zinfo_or_directory_name: str | ZipInfo, _mode: int = 511
    ) -> None:
        pass

    monkeypatch.setattr(ZipFile, "mkdir", skip_mkdir)
    out = workdir / "out.zip"
    code, _, stderr = run("encrypt", str(source), str(out))
    assert code == 1
    assert "expected 8 members but found 6" in stderr
    assert not out.exists()


def test_lost_metadata_is_caught(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = ZipFile.mkdir

    def forgetful(self: ZipFile, info: ZipInfo, mode: int = 511) -> None:
        info.comment = b""
        original(self, info, mode)

    monkeypatch.setattr(ZipFile, "mkdir", forgetful)
    code, _, stderr = run("encrypt", str(source), str(workdir / "out.zip"))
    assert code == 1
    assert "docs/: name, date, mode, comment or extra fields differ" in stderr


def test_lost_extra_fields_are_caught(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = ZipFile.mkdir

    def forgetful(self: ZipFile, info: ZipInfo, mode: int = 511) -> None:
        info.extra = b""
        original(self, info, mode)

    monkeypatch.setattr(ZipFile, "mkdir", forgetful)
    code, _, stderr = run("encrypt", str(source), str(workdir / "out.zip"))
    assert code == 1
    assert "docs/: name, date, mode, comment or extra fields differ" in stderr


def test_a_lost_archive_comment_is_caught(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Forgetful(ZipFile):
        @property
        @override
        def comment(self) -> bytes:
            return super().comment

        @comment.setter
        @override
        def comment(self, comment: bytes) -> None:
            pass

    monkeypatch.setattr("zipctl.cli.commands.helpers.copying.copy.ZipFile", Forgetful)
    code, _, stderr = run("encrypt", str(source), str(workdir / "out.zip"))
    assert code == 1
    assert "the archive comment differs" in stderr


def test_an_unreadable_output_is_reported(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zipctl.exceptions import BadZipFile

    real = ZipFile

    def flaky(
        path: Path, mode: Literal["r", "w", "x", "a"] = "r", *, limits: object = None
    ) -> ZipFile:
        del limits
        if mode == "r":
            raise BadZipFile("File is not a zip file")
        return real(path, mode)

    monkeypatch.setattr("zipctl.cli.commands.helpers.copying.verify.ZipFile", flaky)
    code, _, stderr = run("encrypt", str(source), str(workdir / "out.zip"))
    assert code == 1
    assert "cannot be read back: File is not a zip file" in stderr
    assert not (workdir / "out.zip").exists()


def test_a_healthy_run_reads_the_output_back_and_says_so(
    run: Run, workdir: Path, source: Path
) -> None:
    code, stdout, _ = run("encrypt", str(source), str(workdir / "out.zip"))
    assert code == 0
    assert stdout.rstrip().endswith("(verified)")
    assert snapshot(workdir / "out.zip", PW) == snapshot(source)


def test_a_write_failure_midway_leaves_nothing(
    run: Run, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def full_disk(_self: ZipWriteFile, _data: ReadableBuffer, /) -> int:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(ZipWriteFile, "write", full_disk)
    out = workdir / "out.zip"
    code, _, stderr = run(*RECOMPRESS, str(source), str(out))
    assert code == 1
    assert "cannot copy docs/readme.txt: [Errno 28] No space left on device" in stderr
    assert not out.exists()
    assert leftovers(workdir) == []


@pytest.mark.parametrize(("method", "hint"), [("lzma", False), ("zstd", True)])
def test_a_compression_method_this_install_lacks_is_refused_up_front(
    run: Run,
    workdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    hint: bool,
) -> None:
    from zipctl.compression import registry

    def missing(_method: int) -> None:
        raise RuntimeError("not installed")

    monkeypatch.setattr(registry, "check_compression", missing)
    source = make_source(workdir / "in.zip")
    code, _, stderr = run(
        "rewrite", str(source), str(workdir / "out.zip"), "--compression", method
    )
    assert code == 2, stderr
    assert f"compression method '{method}' is not available" in stderr
    assert ("zipctl[zstd]" in stderr) is hint
    assert not (workdir / "out.zip").exists()
