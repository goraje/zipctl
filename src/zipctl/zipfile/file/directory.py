"""The central directory of a ZipFile: its entries and archive comment."""

from __future__ import annotations

from typing import IO

from zipctl.limits import ArchiveLimits
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.records import read_directory, write_directory

__all__ = ["CentralDirectory"]


class CentralDirectory:
    """The archive's entries, comment, and where its directory starts.

    Attributes:
        infos: Entries in directory order; duplicates are kept.
        by_name: The last entry of each name.
        comment: The archive comment.
        start_dir: Offset of the central directory, which is also where the
            next entry of an archive being written goes.
        modified: Whether the directory must be written out on close.
    """

    def __init__(self, start_dir: int = 0) -> None:
        self.infos: list[ZipInfo] = []
        self.by_name: dict[str, ZipInfo] = {}
        self.comment: bytes = b""
        self.start_dir: int = start_dir
        self.modified: bool = False

    def load(
        self,
        fp: IO[bytes],
        metadata_encoding: str | None,
        debug: int,
        limits: ArchiveLimits,
    ) -> None:
        """Read the directory of the archive in *fp*.

        Raises:
            BadZipFile: If *fp* is not a ZIP archive or its directory is corrupt.
        """
        directory = read_directory(fp, metadata_encoding, debug, limits)
        self.comment = directory.comment
        self.start_dir = directory.start_dir
        for info in directory.infos:
            self.add(info)

    def add(self, zinfo: ZipInfo) -> None:
        """Register a fully written (or just read) entry."""
        self.infos.append(zinfo)
        self.by_name[zinfo.filename] = zinfo

    def write(self, fp: IO[bytes], *, allow_zip64: bool, truncate: bool) -> None:
        """Write the directory and end records at :attr:`start_dir`, then flush.

        *truncate* drops whatever followed (an old directory, or bytes of a
        failed member) from a seekable file.

        Raises:
            LargeZipFile: If ZIP64 is required but not allowed.
        """
        if truncate:
            fp.seek(self.start_dir)
        write_directory(
            fp, self.infos, self.start_dir, self.comment, allow_zip64=allow_zip64
        )
        if truncate:
            fp.truncate()
        fp.flush()
