"""Opening, positioning and closing the stream behind a ZipFile."""

# Friend access inside the zipfile package (ruff exempts it via SLF001).
# pyright: reportPrivateUsage=false

from __future__ import annotations

from typing import IO, TYPE_CHECKING, cast

from zipctl.exceptions import BadZipFile
from zipctl.zipfile.io_wrappers import Tellable
from zipctl.zipfile.records import write_directory

if TYPE_CHECKING:
    from zipctl.zipfile.file import ZipFile

# File modes tried in order when opening an archive path: appending falls back
# to creating the file, and a read/write handle falls back to write-only.
OPEN_MODES = {
    "r": ("rb",),
    "w": ("w+b", "wb"),
    "x": ("x+b", "xb"),
    "a": ("r+b", "w+b", "wb"),
}


def open_archive_file(path: str, mode: str) -> IO[bytes]:
    *fallbacks, last = OPEN_MODES[mode]
    for file_mode in fallbacks:
        try:
            return open(path, file_mode)
        except OSError:
            continue
    return open(path, last)


def start_new_archive(zf: ZipFile) -> None:
    """Position a new archive at the stream's current offset."""
    assert zf.fp is not None
    zf._did_modify = True
    try:
        zf.start_dir = zf.fp.tell()
    except (AttributeError, OSError):
        zf.fp = cast(IO[bytes], Tellable(zf.fp))  # pyright: ignore[reportInvalidCast]  # duck-typed
        zf.start_dir = 0
        zf._seekable = False
    else:
        try:
            zf.fp.seek(zf.start_dir)
        except (AttributeError, OSError):
            zf._seekable = False


def start_appending(zf: ZipFile) -> None:
    """Append to an existing archive, or to the stream's end if it is not one."""
    assert zf.fp is not None
    try:
        zf._read_directory()
        zf.fp.seek(zf.start_dir)
    except BadZipFile:
        zf.fp.seek(0, 2)
        zf._did_modify = True
        zf.start_dir = zf.fp.tell()


def close_archive(zf: ZipFile) -> None:
    zf._write_coordinator.wait_for_finalization()
    if zf.fp is None:
        return
    if zf._write_coordinator.active:
        raise ValueError(
            "Can't close the ZIP file while there is "
            "an open writing handle on it. "
            "Close the writing handle before closing the zip."
        )

    try:
        if zf._write_failed:
            raise ValueError("Cannot finalize a failed non-seekable archive")
        if zf.mode in ("w", "x", "a") and zf._did_modify:
            if zf._seekable:
                zf.fp.seek(zf.start_dir)
            write_end_record(zf)
    finally:
        zf._aes_keys.clear()
        fp = zf.fp
        zf.fp = None
        zf._fpclose(fp)


def write_end_record(zf: ZipFile) -> None:
    """Write the central directory and end records, then flush.

    Truncates seekable output afterwards, removing an old directory or
    abandoned bytes from a failed member write.

    Raises:
        LargeZipFile: If ZIP64 is required but not allowed.
    """
    assert zf.fp is not None
    write_directory(
        zf.fp,
        zf.filelist,
        zf.start_dir,
        zf._comment,
        allow_zip64=zf._allow_zip64,
    )
    if zf._seekable:
        zf.fp.truncate()
    zf.fp.flush()
