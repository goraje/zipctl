"""What the record codec keeps of each entry's on-disk records, seen through ZipFile."""

from __future__ import annotations

import copy
import io
import struct

import pytest

import zipctl
from zipctl import ZipFile
from zipctl.exceptions import BadZipFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.shared import CENTRAL_DIR_SIGNATURE, MASK_UTF_FILENAME

PASSWORD = b"password"
PAYLOAD = b"record payload " * 4


def _zipcrypto_archive() -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", encryption=zipctl.ZIP_CRYPTO) as zf:
        zf.setpassword(PASSWORD)
        zf.writestr(ZipInfo("f", (2020, 5, 6, 7, 8, 10)), PAYLOAD)
    return buffer.getvalue()


@pytest.mark.parametrize("as_copy", [False, True])
def test_a_zipcrypto_check_uses_the_stored_time(as_copy: bool) -> None:
    # The check byte of an entry with a data descriptor comes from the DOS time
    # in its header, whatever date_time says now.
    with ZipFile(io.BytesIO(_zipcrypto_archive())) as zf:
        info = zf.getinfo("f")
        if as_copy:
            info = copy.copy(info)
        info.date_time = (2021, 1, 2, 23, 59, 58)
        assert zf.read(info, pwd=PASSWORD) == PAYLOAD


def test_a_zipcrypto_entry_appended_reads_back_before_close() -> None:
    buffer = io.BytesIO(_zipcrypto_archive())
    with ZipFile(buffer, "a", encryption=zipctl.ZIP_CRYPTO) as zf:
        zf.setpassword(PASSWORD)
        zf.writestr(ZipInfo("g", (2022, 3, 4, 13, 14, 16)), b"appended")
        assert zf.read("g") == b"appended"
        assert zf.read("f") == PAYLOAD


def _overlapping_archive() -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as zf:
        zf.writestr("a", b"a")
        zf.writestr("b", b"b")
    data = bytearray(buffer.getvalue())
    central = data.index(CENTRAL_DIR_SIGNATURE)
    for size_at in (18, 22, central + 20, central + 24):
        struct.pack_into("<L", data, size_at, 40)  # "a" runs into "b"
    return bytes(data)


@pytest.mark.parametrize("as_copy", [False, True])
def test_overlapped_entries_are_refused_for_a_copied_info(as_copy: bool) -> None:
    with ZipFile(io.BytesIO(_overlapping_archive())) as zf:
        info = zf.getinfo("a")
        if as_copy:
            info = copy.copy(info)
        with pytest.raises(BadZipFile, match="Overlapped entries"):
            zf.read(info)


def _cp437_archive() -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as zf:
        zf.writestr("x.txt", b"x")
    return buffer.getvalue().replace(b"x.txt", b"\x80.txt")


def test_appending_keeps_the_stored_name_bytes_and_flags() -> None:
    buffer = io.BytesIO(_cp437_archive())
    with ZipFile(buffer, "a") as zf:
        zf.writestr("y.txt", b"y")
    data = buffer.getvalue()
    central = data.index(CENTRAL_DIR_SIGNATURE)
    assert data.count(b"\x80.txt") == 2  # local header and central directory
    assert data[central + 46 : central + 46 + 5] == b"\x80.txt"
    with ZipFile(io.BytesIO(data)) as zf:
        info = zf.getinfo("\N{LATIN CAPITAL LETTER C WITH CEDILLA}.txt")
        assert not info.flag_bits & MASK_UTF_FILENAME
        assert zf.read(info) == b"x"


def test_a_name_with_a_changed_flag_is_refused() -> None:
    # The local header is checked against the flags stored in the directory,
    # not against the flags a fresh encoding of the name would give.
    data = bytearray(_cp437_archive())
    central = data.index(CENTRAL_DIR_SIGNATURE)
    struct.pack_into("<H", data, 6, MASK_UTF_FILENAME)  # local only
    with ZipFile(io.BytesIO(bytes(data))) as zf:
        with pytest.raises(BadZipFile, match="flags or compression method differ"):
            zf.read(zf.infolist()[0])
    assert data[central + 8] == 0


def test_a_copied_info_is_checked_as_it_is_now() -> None:
    with ZipFile(io.BytesIO(_zipcrypto_archive())) as zf:
        info = copy.copy(zf.getinfo("f"))
        info.orig_filename = "g"
        with pytest.raises(BadZipFile, match="File name in directory 'g'"):
            zf.read(info, pwd=PASSWORD)


def test_an_info_at_no_entry_reads_as_a_bad_header() -> None:
    with ZipFile(io.BytesIO(_zipcrypto_archive())) as zf:
        info = ZipInfo("f")
        info.header_offset = 1
        with pytest.raises(BadZipFile, match="Bad magic number for file header"):
            zf.read(info, pwd=PASSWORD)


def test_start_dir_is_where_the_directory_starts() -> None:
    data = _zipcrypto_archive()
    with ZipFile(io.BytesIO(data)) as zf:
        assert zf.start_dir == data.index(CENTRAL_DIR_SIGNATURE)


def test_an_archive_of_no_entries_takes_new_ones() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as zf:
        zf.comment = b"empty"
    with ZipFile(buffer, "a") as zf:
        assert zf.start_dir == 0
        zf.writestr("n", b"new")
    with ZipFile(buffer) as zf:
        assert (zf.read("n"), zf.comment) == (b"new", b"empty")
