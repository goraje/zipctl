"""Parser allocation budgets and built-in decoder memory limits."""

import io
import struct

import pytest

from tests.unit.zipfile.archive_factory import archive_bytes
from zipctl import ArchiveLimits, ArchiveResourceLimitError, ZipFile
from zipctl.compression.zstd import compression_entry


@pytest.mark.parametrize(
    "field", ["max_entries", "max_directory_bytes", "max_metadata_bytes"]
)
def test_parser_limits_before_variable_record_reads(field: str) -> None:
    limits = ArchiveLimits(**{field: 0})
    with pytest.raises(ArchiveResourceLimitError, match=field):
        ZipFile(io.BytesIO(archive_bytes()), limits=limits)


def test_actual_entry_count_checked_when_header_lies() -> None:
    data = bytearray(archive_bytes())
    struct.pack_into("<HH", data, len(data) - 14, 0, 0)
    with pytest.raises(ArchiveResourceLimitError, match="max_entries"):
        ZipFile(io.BytesIO(data), limits=ArchiveLimits(max_entries=0))


def test_metadata_budget_is_cumulative_and_includes_comment() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w") as archive:
        archive.comment = b"1234"
        archive.writestr("abc", b"")
        archive.writestr("def", b"")
    with pytest.raises(ArchiveResourceLimitError, match="max_metadata_bytes"):
        ZipFile(buffer, limits=ArchiveLimits(max_metadata_bytes=9))
    with ZipFile(buffer, limits=ArchiveLimits(max_metadata_bytes=10)) as archive:
        assert len(archive.infolist()) == 2


def test_lzma_dictionary_checked_before_decoder_allocation() -> None:
    with ZipFile(
        io.BytesIO(archive_bytes(14)),
        limits=ArchiveLimits(max_lzma_dictionary_bytes=4096),
    ) as archive:
        with pytest.raises(ArchiveResourceLimitError, match="dictionary"):
            archive.read("file.txt")


@pytest.mark.skipif(
    compression_entry is None, reason="zstandard backend is unavailable"
)
def test_zstd_window_budget() -> None:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=93) as archive:
        archive.writestr("file", b"x" * 100_000)
    with ZipFile(buffer, limits=ArchiveLimits(max_zstd_window_bytes=1024)) as archive:
        with pytest.raises(ArchiveResourceLimitError, match="window"):
            archive.read("file")


def test_limits_set_after_opening_apply_to_later_reads() -> None:
    with ZipFile(io.BytesIO(archive_bytes(14))) as archive:
        assert archive.read("file.txt")
        archive.limits = ArchiveLimits(max_lzma_dictionary_bytes=4096)
        with pytest.raises(ArchiveResourceLimitError, match="dictionary"):
            archive.read("file.txt")


def test_filelist_can_be_replaced_like_the_standard_library_allows() -> None:
    with ZipFile(io.BytesIO(archive_bytes(14))) as archive:
        archive.filelist = []
        archive.NameToInfo = {}
        assert archive.namelist() == []
