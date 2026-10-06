"""Filesystem materialization of archive members.

A member is first *staged*: its filesystem object (symlink, FIFO or regular
file) is created under a temporary name beside its target, and a directory is
created in place.  The staged entry is then *published* under the target name,
or under another name the caller picks.  Where the platform supports it both
steps work relative to an already-validated directory descriptor (``dir_fd``)
with ``O_NOFOLLOW`` semantics, so the check that the parent is safe and the
write into it cannot be separated by a symlink swap.
"""

from __future__ import annotations

import ntpath
import os
import secrets
import shutil
import stat
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Protocol

from zipctl.zipfile.exceptions import (
    ExtractionMaterializationError,
    ExtractionQuotaExceeded,
    ExtractionSecurityError,
)
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.policy import OverwritePolicy
from zipctl.zipfile.secure_fs import SecureExtractionRoot, publish_exclusive
from zipctl.zipfile.validators import entry_mode, has_parent_component

__all__ = ["ByteQuota", "StagedEntry", "staged"]

_TEMP_PREFIX = ".zipctl-"
# O_BINARY keeps Windows from translating line endings in what is written.
_TEMP_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)


@dataclass(frozen=True)
class ByteQuota:
    """Size limits enforced while a member's payload is written.

    ``total_written`` is the number of bytes already extracted for earlier
    members, so ``total_limit`` applies across the whole extraction.
    ``on_write`` is told the size of every chunk once it is written.
    """

    member_limit: int | None = None
    total_limit: int | None = None
    total_written: int = 0
    on_write: Callable[[int], None] | None = None


class _Writer(Protocol):
    def write(self, data: bytes, /) -> int: ...


class _QuotaWriter:
    """Write-through wrapper that raises once a size limit would be exceeded."""

    def __init__(self, target: _Writer, quota: ByteQuota) -> None:
        self._target: _Writer = target
        self._quota: ByteQuota = quota
        self._member_written: int = 0

    def write(self, data: bytes) -> int:
        member_total = self._member_written + len(data)
        member_limit = self._quota.member_limit
        total_limit = self._quota.total_limit
        if member_limit is not None and member_total > member_limit:
            raise ExtractionQuotaExceeded("actual_member_size", member_limit)
        if (
            total_limit is not None
            and self._quota.total_written + member_total > total_limit
        ):
            raise ExtractionQuotaExceeded("actual_total_uncompressed_size", total_limit)
        written = self._target.write(data)
        self._member_written += written
        if self._quota.on_write is not None:
            self._quota.on_write(written)
        return written


@dataclass
class StagedEntry:
    """A member staged beside its target, waiting to be published.

    ``temp`` is ``None`` for a directory, which is created in place and needs
    no publishing; ``existed`` then says whether it was there already.
    """

    directory: str
    dir_fd: int | None
    overwrite: OverwritePolicy
    temp: str | None = None
    size: int = 0
    existed: bool = False

    def publish(self, target: Path) -> bool:
        """Move the staged entry to *target*, a sibling of the member's target.

        Returns whether an existing entry was replaced, which only
        ``OverwritePolicy.REPLACE`` does.

        Raises:
            FileExistsError: If *target* exists and the policy is not REPLACE.
        """
        assert self.temp is not None
        name = target.name if self.dir_fd is not None else os.fspath(target)
        if self.overwrite != OverwritePolicy.REPLACE:
            publish_exclusive(self.temp, name, self.dir_fd)
            return False
        leaf = _lstat_leaf(name, self.dir_fd)
        if leaf is not None and stat.S_ISDIR(leaf.st_mode):
            raise ExtractionMaterializationError(
                "Refusing to replace an existing directory"
            )
        os.replace(self.temp, name, src_dir_fd=self.dir_fd, dst_dir_fd=self.dir_fd)
        return leaf is not None


def _lstat_leaf(name: str, dir_fd: int | None) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _leaf_reference(
    targetpath: str, dir_fd: int | None, *operations: Callable[..., object]
) -> str:
    """Return the leaf name relative to *dir_fd*, or the full path without one.

    Where the parents were opened by descriptor, every operation must take
    one too: falling back to a path there would reopen the race the
    descriptor closes, so it is refused instead.
    """
    if dir_fd is None:
        return targetpath
    if not all(op in os.supports_dir_fd for op in operations):
        raise ExtractionSecurityError(
            "This platform cannot create this kind of entry relative to a "
            "directory descriptor"
        )
    return os.path.basename(targetpath)


def _temporary_name(directory: str, dir_fd: int | None) -> str:
    name = f"{_TEMP_PREFIX}{secrets.token_hex(16)}"
    return name if dir_fd is not None else os.path.join(directory, name)


def _open_unique_temp(entry: StagedEntry) -> int:
    """Create a uniquely named temp file as ``entry.temp``; return its descriptor.

    Mode ``0o666`` lets the umask decide the final permissions, as for any
    file a program creates.
    """
    for _ in range(100):
        name = _temporary_name(entry.directory, entry.dir_fd)
        try:
            fd = os.open(name, _TEMP_FLAGS, 0o666, dir_fd=entry.dir_fd)
        except FileExistsError:
            continue
        entry.temp = name
        return fd
    raise OSError("Could not create a unique temporary file for extraction")


def _stage_directory(entry: StagedEntry, targetpath: str) -> None:
    name = _leaf_reference(targetpath, entry.dir_fd, os.mkdir)
    leaf = _lstat_leaf(name, entry.dir_fd)
    if leaf is not None and stat.S_ISLNK(leaf.st_mode):
        raise ExtractionSecurityError(
            "Refusing to traverse symlinked extraction directory"
        )
    entry.existed = leaf is not None and stat.S_ISDIR(leaf.st_mode)
    if entry.existed:
        return
    try:
        os.mkdir(name, dir_fd=entry.dir_fd)
    except FileExistsError:
        recheck = _lstat_leaf(name, entry.dir_fd)
        if recheck is None or not stat.S_ISDIR(recheck.st_mode):
            raise


def _stage_symlink(
    entry: StagedEntry, targetpath: str, root: Path, source: IO[bytes]
) -> None:
    payload = source.read(65537)
    if len(payload) > 65536:
        raise ExtractionSecurityError("Symlink target is too long")
    link_target = os.fsdecode(payload)
    if "\0" in link_target:
        raise ExtractionSecurityError("Symlink target contains a NUL byte")
    if (
        os.path.isabs(link_target)
        # Rooted or drive-relative on Windows ("\\x", "C:x"), wherever we run.
        or link_target.startswith(("/", "\\"))
        or ntpath.splitdrive(link_target)[0]
        or has_parent_component(link_target)
    ):
        raise ExtractionSecurityError(
            "Refusing to create symlink outside extraction root"
        )
    try:
        resolved = (Path(entry.directory) / link_target).resolve()
    except RuntimeError:  # a symlink loop, before Python 3.13
        raise ExtractionSecurityError("Symlink target is a symlink loop") from None
    if not resolved.is_relative_to(root):
        raise ExtractionSecurityError(
            "Refusing to create symlink outside extraction root"
        )
    _leaf_reference(targetpath, entry.dir_fd, os.symlink, os.link, os.rename, os.unlink)
    temp = _temporary_name(entry.directory, entry.dir_fd)
    os.symlink(link_target, temp, dir_fd=entry.dir_fd)
    entry.temp = temp


def _stage_special(entry: StagedEntry, targetpath: str, member: ZipInfo) -> None:
    if not (stat.S_ISFIFO(entry_mode(member)) and hasattr(os, "mkfifo")):
        raise ExtractionMaterializationError("Unsupported special file type")
    _leaf_reference(targetpath, entry.dir_fd, os.mkfifo, os.link, os.rename, os.unlink)
    temp = _temporary_name(entry.directory, entry.dir_fd)
    # Permission bits only: never setuid, setgid or sticky from an archive.
    os.mkfifo(temp, (member.external_attr >> 16) & 0o777, dir_fd=entry.dir_fd)
    entry.temp = temp


def _stage_regular_file(
    entry: StagedEntry,
    targetpath: str,
    open_member: Callable[[], IO[bytes]],
    quota: ByteQuota,
    fsync: bool,
) -> None:
    """Write the member to a temp file, so a failure leaves the target alone."""
    name = _leaf_reference(
        targetpath, entry.dir_fd, os.open, os.rename, os.link, os.unlink
    )
    leaf = _lstat_leaf(name, entry.dir_fd)
    if (
        leaf is not None
        and stat.S_ISDIR(leaf.st_mode)
        and entry.overwrite == OverwritePolicy.REPLACE
    ):
        raise ExtractionMaterializationError(
            "Refusing to replace an existing directory with a file"
        )
    unobserved = (
        quota.member_limit is None
        and quota.total_limit is None
        and quota.on_write is None
    )
    with os.fdopen(_open_unique_temp(entry), "wb") as target, open_member() as source:
        sink: _Writer = target if unobserved else _QuotaWriter(target, quota)
        shutil.copyfileobj(source, sink)
        target.flush()
        if fsync:
            os.fsync(target.fileno())
        entry.size = target.tell()


@contextmanager
def staged(
    member: ZipInfo,
    target: Path,
    root: SecureExtractionRoot,
    open_member: Callable[[], IO[bytes]],
    quota: ByteQuota,
    overwrite: OverwritePolicy,
    fsync: bool = True,
) -> Generator[StagedEntry]:
    """Stage *member* beside *target*; the temp entry is removed on exit.

    Missing parent directories are created below the open *root* without
    following symlinks.  Regular files are fsynced before they
    can be published unless *fsync* is ``False``.  The parent stays open as a
    descriptor until exit, so every publish goes to the directory checked.
    """
    targetpath = os.fspath(target)
    parent = os.path.dirname(targetpath)
    dir_fd = root.open_parent(parent) if parent else None
    entry = StagedEntry(parent or ".", dir_fd, overwrite)
    try:
        mode = entry_mode(member)
        if member.is_dir():
            _stage_directory(entry, targetpath)
        elif stat.S_ISLNK(mode):
            with open_member() as source:
                _stage_symlink(entry, targetpath, root.path, source)
        elif mode and not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
            _stage_special(entry, targetpath, member)
        else:
            _stage_regular_file(entry, targetpath, open_member, quota, fsync)
        yield entry
    finally:
        try:
            if entry.temp is not None:
                with suppress(FileNotFoundError):
                    os.unlink(entry.temp, dir_fd=dir_fd)
        finally:
            if dir_fd is not None:
                os.close(dir_fd)
