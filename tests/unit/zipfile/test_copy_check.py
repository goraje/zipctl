"""Checking a member copy against what ``copy_member`` promises."""

from __future__ import annotations

import dataclasses
import io
import struct
from collections.abc import Callable, Generator
from contextlib import ExitStack
from typing import NamedTuple, NoReturn, TypedDict

import pytest
from typing_extensions import Unpack, override

import zipctl
from zipctl import CopiedMember, ZipFile
from zipctl.zipfile.file.copy_check import copy_problem
from zipctl.zipfile.info import ZipInfo

PASSWORD = b"correct horse"
DATE = (2020, 1, 2, 3, 4, 6)
METADATA = "name, date, mode, comment or extra fields differ"
COMPRESSED = "the compressed data was not copied as it was"
STORED = "the stored data was not copied as it was"
DIFFERS = "the data read back differs from the data copied"


class CopyOptions(TypedDict, total=False):
    """The keyword-only parameters of ``ZipFile.copy_member`` these tests use."""

    pwd: bytes | None
    compress_type: int | None
    encryption: str | None
    password: bytes | None
    keep_encryption: bool


class Copy(NamedTuple):
    source: ZipFile
    member: ZipInfo
    copy: ZipFile
    new: ZipInfo  # as read back from the copy
    copied: CopiedMember


def _deflated(name: str) -> ZipInfo:
    info = ZipInfo(name, DATE)
    info.compress_type = zipctl.ZIP_DEFLATED
    return info


def make_source() -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as zf:
        zf.mkdir(ZipInfo("d/", DATE))
        zf.writestr(_deflated("p.txt"), b"plain text " * 50)
        zf.writestr(
            _deflated("e.txt"),
            b"secret text " * 50,
            encryption=zipctl.WZ_AES,
            password=PASSWORD,
        )
    return buffer.getvalue()


MakeCopy = Callable[..., Copy]


@pytest.fixture
def copy_of() -> Generator[MakeCopy]:
    """Copy one member of a fresh source archive and read the copy back."""
    with ExitStack() as stack:

        def go(
            name: str, source: bytes | None = None, **kw: Unpack[CopyOptions]
        ) -> Copy:
            src = stack.enter_context(ZipFile(io.BytesIO(source or make_source())))
            member = src.getinfo(name)
            buffer = io.BytesIO()
            with ZipFile(buffer, "w") as dst:
                copied = dst.copy_member(src, member, **kw)
            out = stack.enter_context(ZipFile(io.BytesIO(buffer.getvalue())))
            return Copy(src, member, out, out.getinfo(name), copied)

        yield go


def check(c: Copy, *, pwd: bytes | None = None, kept: bool = False) -> str | None:
    return copy_problem(c.source, c.member, c.copy, c.new, c.copied, pwd=pwd, kept=kept)


HEALTHY: dict[str, tuple[str, CopyOptions, bytes | None, bool]] = {
    "directory": ("d/", {}, None, False),
    "compressed data copied": ("p.txt", {}, None, False),
    "compressed again": ("p.txt", {"compress_type": zipctl.ZIP_STORED}, None, False),
    "decrypted": ("e.txt", {"pwd": PASSWORD}, None, False),
    "encrypted again": (
        "e.txt",
        {"pwd": PASSWORD, "encryption": zipctl.ZIP_CRYPTO, "password": b"new"},
        b"new",
        False,
    ),
    "kept encrypted": ("e.txt", {"keep_encryption": True}, None, True),
}


@pytest.mark.parametrize(
    ("name", "options", "pwd", "kept"), HEALTHY.values(), ids=HEALTHY
)
def test_a_faithful_copy_has_no_problem(
    copy_of: MakeCopy, name: str, options: CopyOptions, pwd: bytes | None, kept: bool
) -> None:
    assert check(copy_of(name, **options), pwd=pwd, kept=kept) is None


_TIMESTAMP = struct.pack("<HHBI", 0x5455, 5, 1, 0)  # an extended timestamp field

METADATA_CHANGES: dict[str, Callable[[ZipInfo], None]] = {
    "filename": lambda i: setattr(i, "filename", "q.txt"),
    "date_time": lambda i: setattr(i, "date_time", (2021, 1, 2, 3, 4, 6)),
    "external_attr": lambda i: setattr(i, "external_attr", i.external_attr ^ 1 << 16),
    "internal_attr": lambda i: setattr(i, "internal_attr", i.internal_attr ^ 1),
    "create_system": lambda i: setattr(i, "create_system", i.create_system ^ 1),
    "comment": lambda i: setattr(i, "comment", b"changed"),
    "carried extra field": lambda i: setattr(i, "extra", i.extra + _TIMESTAMP),
}


@pytest.mark.parametrize("change", METADATA_CHANGES.values(), ids=METADATA_CHANGES)
@pytest.mark.parametrize("name", ["d/", "p.txt"])
def test_changed_metadata_is_a_problem(
    copy_of: MakeCopy, name: str, change: Callable[[ZipInfo], None]
) -> None:
    c = copy_of(name)
    change(c.new)
    assert check(c) == METADATA


RAW_CHANGES: dict[str, Callable[[ZipInfo], None]] = {
    "compress_type": lambda i: setattr(i, "compress_type", zipctl.ZIP_STORED),
    "compression option bits": lambda i: setattr(i, "flag_bits", i.flag_bits ^ 0b010),
    "file_size": lambda i: setattr(i, "file_size", i.file_size + 1),
}


@pytest.mark.parametrize("change", RAW_CHANGES.values(), ids=RAW_CHANGES)
def test_compressed_data_not_copied_as_it_was_is_a_problem(
    copy_of: MakeCopy, change: Callable[[ZipInfo], None]
) -> None:
    c = copy_of("p.txt")
    assert c.copied.raw
    change(c.new)
    assert check(c) == COMPRESSED


def test_other_flag_bits_of_a_compressed_copy_are_not_compared(
    copy_of: MakeCopy,
) -> None:
    c = copy_of("p.txt")
    c.new.flag_bits ^= 1 << 11  # the UTF-8 name flag
    assert check(c) is None


COPIED_CHANGES: dict[str, Callable[[CopiedMember], CopiedMember]] = {
    "crc": lambda m: dataclasses.replace(m, crc=(m.crc or 0) ^ 1),
    "size": lambda m: dataclasses.replace(m, size=m.size + 1),
}


@pytest.mark.parametrize("copied", COPIED_CHANGES.values(), ids=COPIED_CHANGES)
def test_data_that_reads_back_differently_is_a_problem(
    copy_of: MakeCopy, copied: Callable[[CopiedMember], CopiedMember]
) -> None:
    c = copy_of("p.txt", compress_type=zipctl.ZIP_STORED)
    assert check(c._replace(copied=copied(c.copied))) == DIFFERS


@pytest.mark.parametrize("pwd", [None, b"wrong"])
def test_a_copy_that_cannot_be_read_back_names_the_failure(
    copy_of: MakeCopy, pwd: bytes | None
) -> None:
    c = copy_of("e.txt", pwd=PASSWORD, encryption=zipctl.ZIP_CRYPTO, password=b"new")
    with pytest.raises(Exception) as caught:  # noqa: PT011  # whatever open raises
        c.copy.open(c.new, pwd=pwd).read()
    assert check(c, pwd=pwd) == str(caught.value)


KEPT_CHANGES: dict[str, Callable[[ZipInfo], None]] = {
    "CRC": lambda i: setattr(i, "CRC", i.CRC ^ 1),
    "compress_size": lambda i: setattr(i, "compress_size", i.compress_size + 1),
    "flag bits": lambda i: setattr(i, "flag_bits", i.flag_bits ^ 1 << 3),
}


@pytest.mark.parametrize("change", KEPT_CHANGES.values(), ids=KEPT_CHANGES)
def test_a_kept_member_whose_header_changed_is_a_problem(
    copy_of: MakeCopy, change: Callable[[ZipInfo], None]
) -> None:
    c = copy_of("e.txt", keep_encryption=True)
    change(c.new)
    assert check(c, kept=True) == STORED


def test_a_kept_member_may_have_its_name_marked_utf8(copy_of: MakeCopy) -> None:
    c = copy_of("e.txt", keep_encryption=True)
    c.new.flag_bits ^= 1 << 11
    assert check(c, kept=True) is None


def test_kept_bytes_are_compared_byte_for_byte(copy_of: MakeCopy) -> None:
    # The same member encrypted twice: equal headers, other salt and bytes.
    c = copy_of("e.txt", keep_encryption=True)
    other = ZipFile(io.BytesIO(make_source()))
    twin = other.getinfo("e.txt")
    header = ("date_time", "flag_bits", "CRC", "compress_size", "file_size")
    assert [getattr(twin, f) for f in header] == [getattr(c.member, f) for f in header]
    with other:
        assert check(c._replace(source=other, member=twin), kept=True) == STORED


def test_a_failure_without_a_message_is_named_by_its_type(
    copy_of: MakeCopy, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: object, **_kw: object) -> NoReturn:
        raise OSError

    c = copy_of("p.txt")
    monkeypatch.setattr(c.copy, "open", broken)
    assert check(c) == "OSError"


class ShortReads(io.BytesIO):
    """A source that never returns more than 7 bytes per read."""

    @override
    def read(self, size: int | None = -1, /) -> bytes:
        return super().read(7 if size is None or not 0 <= size <= 7 else size)


def test_a_kept_copy_from_a_source_with_short_reads_holds() -> None:
    with ZipFile(ShortReads(make_source())) as src:
        member = src.getinfo("e.txt")
        buffer = io.BytesIO()
        with ZipFile(buffer, "w") as dst:
            copied = dst.copy_member(src, member, keep_encryption=True)
        with ZipFile(io.BytesIO(buffer.getvalue())) as out:
            c = Copy(src, member, out, out.getinfo("e.txt"), copied)
            assert check(c, kept=True) is None
