"""The central directory: one record per entry, read and written as a whole."""

from __future__ import annotations

import struct
from dataclasses import replace
from typing import IO

from zipctl.cryptography.aes import WZ_AES_COMPRESS_TYPE
from zipctl.exceptions import BadZipFile, LargeZipFile
from zipctl.limits import ArchiveLimits
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.io_wrappers import write_all
from zipctl.zipfile.records.end import EndRecord, read_end_record, write_end_records
from zipctl.zipfile.records.extra import decode_extra, zip64_central_extra
from zipctl.zipfile.records.header import (
    encode_extra,
    encode_filename_flags,
    minimum_version,
)
from zipctl.zipfile.records.local import (
    DirectoryEntry,
    data_end,
    read_exactly,
)
from zipctl.zipfile.shared import (
    CENTRAL_DIR_SIGNATURE,
    CENTRAL_DIR_SIZE,
    CENTRAL_DIR_STRUCT,
    FILE_HEADER_SIZE,
    MASK_UTF_FILENAME,
    MAX_EXTRACT_VERSION,
    crc32,
    needs_zip64,
)

__all__ = ["Directory", "looks_like_zip"]

# Field positions in the unpacked struct tuple.
_CD_SIGNATURE = 0
_CD_CREATE_VERSION = 1
_CD_CREATE_SYSTEM = 2
_CD_EXTRACT_VERSION = 3
_CD_EXTRACT_SYSTEM = 4
_CD_FLAG_BITS = 5
_CD_COMPRESS_TYPE = 6
_CD_TIME = 7
_CD_DATE = 8
_CD_CRC = 9
_CD_COMPRESSED_SIZE = 10
_CD_UNCOMPRESSED_SIZE = 11
_CD_FILENAME_LENGTH = 12
_CD_EXTRA_FIELD_LENGTH = 13
_CD_COMMENT_LENGTH = 14
_CD_DISK_NUMBER_START = 15
_CD_INTERNAL_FILE_ATTRIBUTES = 16
_CD_EXTERNAL_FILE_ATTRIBUTES = 17
_CD_LOCAL_HEADER_OFFSET = 18


def looks_like_zip(fp: IO[bytes]) -> bool:
    """Return ``True`` if *fp* has a plausible ZIP structure.

    Reads the end-of-central-directory record and, unless the archive is
    empty, checks the signature of the first central directory entry.
    """
    try:
        record = read_end_record(fp)
        if not record:
            return False
        if record.entries_total == 0 and record.size == 0 and record.offset == 0:
            return True
        if record.disk_number == record.disk_start and record.directory_start >= 0:
            fp.seek(record.directory_start)
            if record.size >= CENTRAL_DIR_SIZE:
                data = fp.read(CENTRAL_DIR_SIZE)
                if len(data) == CENTRAL_DIR_SIZE:
                    header = struct.unpack(CENTRAL_DIR_STRUCT, data)
                    return bool(header[_CD_SIGNATURE] == CENTRAL_DIR_SIGNATURE)
    except (OSError, ValueError):
        pass
    return False


def _read_directory_entry(
    stream: IO[bytes],
    metadata_encoding: str | None,
    prepended_bytes: int,
    remaining: int,
    limits: ArchiveLimits,
    metadata_used: int,
) -> tuple[DirectoryEntry, int]:
    """Parse one central directory entry; return it and its declared length."""
    if remaining < CENTRAL_DIR_SIZE:
        raise BadZipFile("Truncated central directory")
    raw = read_exactly(stream, CENTRAL_DIR_SIZE)
    header = struct.unpack(CENTRAL_DIR_STRUCT, raw)
    if header[_CD_SIGNATURE] != CENTRAL_DIR_SIGNATURE:
        raise BadZipFile("Bad magic number for central directory")
    declared_length = (
        CENTRAL_DIR_SIZE
        + header[_CD_FILENAME_LENGTH]
        + header[_CD_EXTRA_FIELD_LENGTH]
        + header[_CD_COMMENT_LENGTH]
    )
    if declared_length > remaining:
        raise BadZipFile("Truncated central directory entry")
    limits.check(
        "max_metadata_bytes", metadata_used + declared_length - CENTRAL_DIR_SIZE
    )
    filename_bytes = read_exactly(stream, header[_CD_FILENAME_LENGTH])
    flags = header[_CD_FLAG_BITS]
    try:
        filename = filename_bytes.decode(
            "utf-8" if flags & MASK_UTF_FILENAME else metadata_encoding or "cp437"
        )
    except UnicodeDecodeError as exc:
        raise BadZipFile("Invalid filename encoding") from exc

    info = ZipInfo(filename)
    info.extra = read_exactly(stream, header[_CD_EXTRA_FIELD_LENGTH])
    info.comment = read_exactly(stream, header[_CD_COMMENT_LENGTH])
    info.header_offset = header[_CD_LOCAL_HEADER_OFFSET]
    info.create_version = header[_CD_CREATE_VERSION]
    info.create_system = header[_CD_CREATE_SYSTEM]
    info.extract_version = header[_CD_EXTRACT_VERSION]
    info.reserved = header[_CD_EXTRACT_SYSTEM]
    info.flag_bits = flags
    info.compress_type = header[_CD_COMPRESS_TYPE]
    dos_time = header[_CD_TIME]
    dos_date = header[_CD_DATE]
    info.CRC = header[_CD_CRC]
    info.compress_size = header[_CD_COMPRESSED_SIZE]
    info.file_size = header[_CD_UNCOMPRESSED_SIZE]
    if info.extract_version > MAX_EXTRACT_VERSION:
        raise NotImplementedError(f"zip file version {info.extract_version / 10:.1f}")
    info.volume = header[_CD_DISK_NUMBER_START]
    info.internal_attr = header[_CD_INTERNAL_FILE_ATTRIBUTES]
    info.external_attr = header[_CD_EXTERNAL_FILE_ATTRIBUTES]
    info.date_time = (
        (dos_date >> 9) + 1980,
        (dos_date >> 5) & 0xF,
        dos_date & 0x1F,
        dos_time >> 11,
        (dos_time >> 5) & 0x3F,
        (dos_time & 0x1F) * 2,
    )
    decode_extra(info, crc32(filename_bytes))
    if info.is_aes != (header[_CD_COMPRESS_TYPE] == WZ_AES_COMPRESS_TYPE) or (
        info.is_aes and not info.is_encrypted
    ):
        raise BadZipFile("Inconsistent AES metadata")
    if info.volume:
        raise BadZipFile("zipfiles that span multiple disks are not supported")
    info.header_offset += prepended_bytes
    if info.header_offset < 0:
        raise BadZipFile("Bad offset for local file header")
    return DirectoryEntry(info, dos_time, (filename_bytes, flags)), declared_length


def _checked_end_record(
    fp: IO[bytes], limits: ArchiveLimits, *, allow_prepended_data: bool
) -> EndRecord:
    try:
        record = read_end_record(fp)
    except OSError:
        raise BadZipFile("File is not a zip file") from None
    if not record:
        raise BadZipFile("File is not a zip file")
    limits.check("max_entries", record.entries_total)
    limits.check("max_directory_bytes", record.size)
    limits.check("max_metadata_bytes", len(record.comment))
    if record.disk_number or record.disk_start:
        raise BadZipFile("zipfiles that span multiple disks are not supported")
    if record.entries_this_disk != record.entries_total:
        raise BadZipFile("End of central directory entry counts differ")
    if record.directory_start < 0:
        raise BadZipFile("Bad offset for central directory")
    if record.prepended_bytes > 0 and not allow_prepended_data:
        raise BadZipFile(
            "Data before the archive (a self-extracting stub?); "
            "pass allow_prepended_data=True to read it"
        )
    return record


def _set_end_offsets(
    entries: list[DirectoryEntry],
    start_dir: int,
    first: int,
    *,
    allow_prepended_data: bool,
) -> None:
    """Give each entry the offset where the next one (or the directory) starts.

    Every byte from *first* up to the directory must belong to an entry; with
    *allow_prepended_data* a stub may also come before entries whose offsets
    already count it (a self-extractor, or a prefixed archive appended to).
    """
    end_offset = start_dir
    for entry in sorted(entries, key=_offset, reverse=True):
        if entry.info.header_offset + FILE_HEADER_SIZE > end_offset:
            raise BadZipFile("Bad offset for local file header")
        entry.end_offset = end_offset
        end_offset = entry.info.header_offset
    if end_offset < first or (end_offset != first and not allow_prepended_data):
        raise BadZipFile("Unaccounted bytes before the first entry")


_APK_SIGNING_MAGIC = b"APK Sig Block 42"


def _signing_block_start(fp: IO[bytes], start_dir: int, first: int) -> int:
    """Where an APK Signing Block before the directory starts, else *start_dir*.

    The block is ``size, pairs, size, magic`` with both 64-bit sizes counting
    everything after the first; 7-Zip and Android tools expect it there.
    """
    if start_dir - first < 32:
        return start_dir
    fp.seek(start_dir - 24)
    footer = read_exactly(fp, 24)
    if footer[8:] != _APK_SIGNING_MAGIC:
        return start_dir
    size = int.from_bytes(footer[:8], "little")
    block_start = start_dir - size - 8
    if size < 24 or block_start < first:
        return start_dir
    fp.seek(block_start)
    if int.from_bytes(read_exactly(fp, 8), "little") != size:
        return start_dir
    return block_start


def _offset(entry: DirectoryEntry) -> int:
    return entry.info.header_offset


def _check_last_extent(fp: IO[bytes], entries: list[DirectoryEntry]) -> None:
    """Refuse unaccounted bytes between the last entry and the directory.

    Reading that entry would refuse them too; finding them here does it on
    open.  A local header that cannot be parsed is left for the read to report.
    """
    if not entries:
        return
    entry = max(entries, key=_offset)
    info = entry.info
    end = data_end(fp, info)
    if end is None:
        return
    gap = (entry.end_offset or 0) - end
    allowed = (12, 16, 20, 24) if info.use_data_descriptor else (0,)
    if gap > 0 and gap not in allowed:
        raise BadZipFile(f"Unaccounted bytes after {info.orig_filename!r}")


def _refuse_duplicate_names(entries: list[DirectoryEntry]) -> None:
    # Readers that pick the first or the last entry would see different files
    # under one name, so such an archive is ambiguous.
    names: set[str] = set()
    for entry in entries:
        if entry.info.filename in names:
            raise BadZipFile(f"Duplicate name: {entry.info.filename!r}")
        names.add(entry.info.filename)


def _central_record(entry: DirectoryEntry) -> bytes:
    """Serialize the central directory record of *entry*."""
    info = entry.info
    extra, file_size, compress_size, header_offset, zip64_version = zip64_central_extra(
        info
    )
    min_version = minimum_version(info, zip64_version)
    filename, flag_bits = entry.stored_name or encode_filename_flags(info)
    wz_aes_extra, crc, compress_type = encode_extra(info, info.CRC, info.compress_type)
    extra += wz_aes_extra
    centdir = struct.pack(
        CENTRAL_DIR_STRUCT,
        CENTRAL_DIR_SIGNATURE,
        max(min_version, info.create_version),
        info.create_system,
        max(min_version, info.extract_version),
        info.reserved,
        flag_bits,
        compress_type,
        info.get_dostime(),
        info.get_dosdate(),
        crc,
        compress_size,
        file_size,
        len(filename),
        len(extra),
        len(info.comment),
        0,  # disk number start: multi-disk archives are not written
        info.internal_attr,
        info.external_attr,
        header_offset,
    )
    return centdir + filename + extra + info.comment


class Directory:
    """The archive's entries, comment, and where its directory starts.

    Attributes:
        infos: Entries in directory order; names are unique.
        by_name: The entry of each name.
        start_dir: Offset of the central directory, which is also where the
            next entry of an archive being written goes.
        modified: Whether the directory must be written out on close.
    """

    def __init__(self) -> None:
        self.infos: list[ZipInfo] = []
        self.by_name: dict[str, ZipInfo] = {}
        self.start_dir: int = 0
        self.modified: bool = False
        self._comment: bytes = b""
        self._entries: list[DirectoryEntry] = []
        # by header offset: a copy of an info still finds its records
        self._at: dict[int, DirectoryEntry] = {}
        self._frozen: tuple[ZipInfo, ...] | None = None

    @property
    def comment(self) -> bytes:
        """The archive comment; setting it marks the directory modified."""
        return self._comment

    @comment.setter
    def comment(self, comment: bytes) -> None:
        self._comment = comment
        self.modified = True

    def frozen(self) -> tuple[ZipInfo, ...]:
        """The entries as a tuple, rebuilt only after an entry is added."""
        if self._frozen is None:
            self._frozen = tuple(self.infos)
        return self._frozen

    def entry(self, info: ZipInfo) -> DirectoryEntry:
        """The records of the entry at *info*'s header offset.

        An info that is not in the directory gets records built from it alone.
        """
        entry = self._at.get(info.header_offset)
        if entry is None:
            return DirectoryEntry(info, info.get_dostime())
        return entry if entry.info is info else replace(entry, info=info)

    def begin(self, start: int) -> None:
        """Start a new, empty directory whose entries go from *start*."""
        self.start_dir = start
        self.modified = True

    def resume(self) -> int:
        """Where entries appended to a loaded directory go, and so the directory.

        That is the end of the last entry: an APK Signing Block after it is
        written over, as new entries void it.
        """
        if self._entries:
            self.start_dir = max(entry.end_offset or 0 for entry in self._entries)
        return self.start_dir

    def add(self, info: ZipInfo, end: int) -> None:
        """Register *info*, an entry just written that ends at *end*."""
        self._add(DirectoryEntry(info, info.get_dostime()))
        self.start_dir = end

    def _add(self, entry: DirectoryEntry) -> None:
        self._entries.append(entry)
        self._at[entry.info.header_offset] = entry
        self.infos.append(entry.info)
        self.by_name[entry.info.filename] = entry.info
        self._frozen = None

    def load(
        self,
        fp: IO[bytes],
        metadata_encoding: str | None = None,
        limits: ArchiveLimits | None = None,
        *,
        allow_prepended_data: bool = False,
    ) -> None:
        """Read the central directory of the archive in *fp*.

        Each entry learns where the next one (or the directory) starts, for
        overlap and gap detection.

        Raises:
            BadZipFile: If *fp* is not a ZIP archive, its central directory is
                truncated or corrupt, or bytes are left unaccounted for.
            NotImplementedError: If an entry needs a newer ZIP version than is
                supported.
        """
        limits = limits or ArchiveLimits()
        record = _checked_end_record(
            fp, limits, allow_prepended_data=allow_prepended_data
        )
        start_dir = record.directory_start
        fp.seek(start_dir)
        entries: list[DirectoryEntry] = []
        consumed = 0
        metadata_used = len(record.comment)
        while consumed < record.size:
            limits.check("max_entries", len(entries) + 1)
            entry, declared_length = _read_directory_entry(
                fp,
                metadata_encoding,
                record.prepended_bytes,
                record.size - consumed,
                limits,
                metadata_used,
            )
            entries.append(entry)
            consumed += declared_length
            metadata_used += declared_length - CENTRAL_DIR_SIZE
        if len(entries) != record.entries_total:
            raise BadZipFile("Central directory entry count mismatch")
        _refuse_duplicate_names(entries)
        first = max(record.prepended_bytes, 0)
        _set_end_offsets(
            entries,
            _signing_block_start(fp, start_dir, first),
            first,
            allow_prepended_data=allow_prepended_data,
        )
        _check_last_extent(fp, entries)
        self._comment = record.comment
        self.start_dir = start_dir
        for entry in entries:
            self._add(entry)

    def write(self, fp: IO[bytes], *, allow_zip64: bool, truncate: bool) -> None:
        """Write the directory and end records at :attr:`start_dir`, then flush.

        *truncate* drops whatever followed (an old directory, or bytes of a
        failed member) from a seekable file.  The ZIP64 end record and locator
        are written only when a count, size or offset exceeds the classic
        limits.

        Raises:
            LargeZipFile: If ZIP64 is required but not allowed.
        """
        # Built first, so a refused directory leaves nothing half written.
        records = b"".join(_central_record(entry) for entry in self._entries)
        count = len(self._entries)
        size = len(records)
        if needs_zip64(count=count):
            reason = "Files count"
        elif needs_zip64(self.start_dir):
            reason = "Central directory offset"
        elif needs_zip64(size):
            reason = "Central directory size"
        else:
            reason = ""
        if reason and not allow_zip64:
            raise LargeZipFile(reason + " would require ZIP64 extensions")
        if truncate:
            fp.seek(self.start_dir)
        write_all(fp, records)
        write_end_records(
            fp, count, size, self.start_dir, self._comment, zip64=bool(reason)
        )
        if truncate:
            fp.truncate()
        fp.flush()
