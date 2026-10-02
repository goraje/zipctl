"""Filesystem materialization of archive members.

Each materializer creates one kind of filesystem object (directory, symlink,
FIFO or regular file) for a member.  Where the platform supports it they work
relative to an already-validated directory descriptor (``dir_fd``) with
``O_NOFOLLOW`` semantics, so the check that the parent is safe and the write
into it cannot be separated by a symlink swap.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
from collections.abc import Callable
from contextlib import suppress
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
from zipctl.zipfile.progress import ProgressReporter
from zipctl.zipfile.secure_fs import open_secure_parent
from zipctl.zipfile.validators import entry_mode, has_parent_component

__all__ = [
    "ExtractionQuota",
    "MaterializationResult",
    "MaterializeParams",
    "Materializer",
    "materialize_member",
    "select_materializer",
]

_TEMP_PREFIX = ".zipctl-"


@dataclass(frozen=True)
class MaterializationResult:
    """Result returned by a member materializer."""

    target: Path
    bytes_written: int
    overwritten: bool = False


@dataclass(frozen=True)
class ExtractionQuota:
    """Size limits enforced while a member's payload is written.

    ``total_written`` is the number of bytes already extracted for earlier
    members, so ``total_limit`` applies across the whole extraction.
    """

    member_limit: int | None = None
    total_limit: int | None = None
    total_written: int = 0
    created_directories: set[Path] | None = None
    validate_target: Callable[[Path], None] | None = None

    @property
    def unbounded(self) -> bool:
        return self.member_limit is None and self.total_limit is None


@dataclass(frozen=True)
class MaterializeParams:
    """Bundles one materializer call's arguments.

    A materializer only reads the fields it needs; for example directory and
    FIFO materialization never open the member's payload.
    """

    member: ZipInfo
    targetpath: str
    open_member: Callable[[], IO[bytes]]
    quota: ExtractionQuota
    directory: str
    dir_fd: int | None
    fsync: bool = True
    reporter: ProgressReporter | None = None
    root: str = "."
    overwrite: OverwritePolicy = OverwritePolicy.REPLACE


class Materializer(Protocol):
    """Protocol for regular-file, directory, symlink and FIFO materializers."""

    def __call__(self, params: MaterializeParams) -> MaterializationResult: ...


class _Writer(Protocol):
    def write(self, data: bytes, /) -> int: ...


class _QuotaWriter:
    """Write-through wrapper that raises once a size limit would be exceeded."""

    def __init__(self, target: _Writer, quota: ExtractionQuota) -> None:
        self._target: _Writer = target
        self._quota: ExtractionQuota = quota
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
        return written


class _ProgressWriter:
    """Write-through wrapper that reports the bytes it passes on."""

    def __init__(self, target: _Writer, reporter: ProgressReporter) -> None:
        self._target: _Writer = target
        self._reporter: ProgressReporter = reporter

    def write(self, data: bytes) -> int:
        written = self._target.write(data)
        self._reporter.advance(written)
        return written


def _lstat_leaf(name: str, dir_fd: int | None) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _leaf_reference(
    params: MaterializeParams, *operations: Callable[..., object]
) -> tuple[str, int | None]:
    """Return ``(name, dir_fd)`` for the leaf, falling back to the full path.

    The descriptor-relative form is used only when the platform supports
    ``dir_fd`` for every operation the caller is about to perform.
    """
    if params.dir_fd is not None and all(op in os.supports_dir_fd for op in operations):
        return os.path.basename(params.targetpath), params.dir_fd
    return params.targetpath, None


def _open_unique_temp(directory: str, dir_fd: int | None) -> tuple[str, int]:
    """Create a uniquely named temp file; return its name and descriptor.

    The name is relative to *dir_fd* when one is given, else a path inside
    *directory*.  Mode ``0o666`` lets the umask decide the final permissions,
    as for any file a program creates.
    """
    for _ in range(100):
        name = _temporary_name(directory, dir_fd)
        try:
            fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666, dir_fd=dir_fd
            )
        except FileExistsError:
            continue
        return name, fd
    raise OSError("Could not create a unique temporary file for extraction")


def _copy_payload(params: MaterializeParams, target: IO[bytes]) -> int:
    """Stream the member into *target*, fsync it, and return the byte count."""
    sink: _Writer = target
    if not params.quota.unbounded:
        sink = _QuotaWriter(sink, params.quota)
    if params.reporter is not None:
        sink = _ProgressWriter(sink, params.reporter)
    with params.open_member() as source:
        shutil.copyfileobj(source, sink)
    target.flush()
    if params.fsync:
        os.fsync(target.fileno())
    return target.tell()


def materialize_directory(params: MaterializeParams) -> MaterializationResult:
    name, dir_fd = _leaf_reference(params, os.mkdir)
    leaf = _lstat_leaf(name, dir_fd)
    if leaf is not None and stat.S_ISLNK(leaf.st_mode):
        raise ExtractionSecurityError(
            "Refusing to traverse symlinked extraction directory"
        )
    existed = leaf is not None and stat.S_ISDIR(leaf.st_mode)
    if not existed:
        try:
            os.mkdir(name, dir_fd=dir_fd)
        except FileExistsError:
            recheck = _lstat_leaf(name, dir_fd)
            if recheck is None or not stat.S_ISDIR(recheck.st_mode):
                raise
        else:
            if params.quota.created_directories is not None:
                params.quota.created_directories.add(Path(params.targetpath))
    return MaterializationResult(Path(params.targetpath), 0, existed)


def materialize_symlink(params: MaterializeParams) -> MaterializationResult:
    with params.open_member() as source:
        payload = source.read(65537)
    if len(payload) > 65536:
        raise ExtractionSecurityError("Symlink target is too long")
    link_target = os.fsdecode(payload)
    if "\0" in link_target:
        raise ExtractionSecurityError("Symlink target contains a NUL byte")
    if os.path.isabs(link_target) or has_parent_component(link_target):
        raise ExtractionSecurityError(
            "Refusing to create symlink outside extraction root"
        )
    resolved = (Path(params.directory) / link_target).resolve()
    if not resolved.is_relative_to(Path(params.root).resolve()):
        raise ExtractionSecurityError(
            "Refusing to create symlink outside extraction root"
        )
    name, dir_fd = _leaf_reference(params, os.symlink, os.link, os.rename, os.unlink)
    temp = _temporary_name(params.directory, dir_fd)
    os.symlink(link_target, temp, dir_fd=dir_fd)
    try:
        return _commit_temp(params, temp, name, dir_fd, 0)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temp, dir_fd=dir_fd)


def materialize_special(params: MaterializeParams) -> MaterializationResult:
    member = params.member
    if stat.S_ISFIFO(entry_mode(member)) and hasattr(os, "mkfifo"):
        name, dir_fd = _leaf_reference(params, os.mkfifo, os.link, os.rename, os.unlink)
        temp = _temporary_name(params.directory, dir_fd)
        os.mkfifo(temp, stat.S_IMODE(member.external_attr >> 16), dir_fd=dir_fd)
        try:
            return _commit_temp(params, temp, name, dir_fd, 0)
        finally:
            with suppress(FileNotFoundError):
                os.unlink(temp, dir_fd=dir_fd)
    raise ExtractionMaterializationError("Unsupported special file type")


def materialize_regular_file(params: MaterializeParams) -> MaterializationResult:
    """Write the member to a temp file and atomically move it into place.

    Existing files are therefore preserved when the member fails part-way.
    """
    name, dir_fd = _leaf_reference(params, os.open, os.rename, os.link, os.unlink)
    leaf = _lstat_leaf(name, dir_fd)
    if (
        leaf is not None
        and stat.S_ISDIR(leaf.st_mode)
        and params.overwrite == OverwritePolicy.REPLACE
    ):
        raise ExtractionMaterializationError(
            "Refusing to replace an existing directory with a file"
        )
    temp_name: str | None = None
    try:
        temp_name, fd = _open_unique_temp(params.directory, dir_fd)
        with os.fdopen(fd, "wb") as target:
            bytes_written = _copy_payload(params, target)
        return _commit_temp(params, temp_name, name, dir_fd, bytes_written)
    finally:
        if temp_name is not None:
            with suppress(FileNotFoundError):
                os.unlink(temp_name, dir_fd=dir_fd)


def select_materializer(member: ZipInfo, *, plain: bool = False) -> Materializer:
    """Return the materializer matching *member*'s entry type.

    *plain* writes symlink and special-file members as regular files holding
    their payload, as the standard library's ``zipfile`` does.
    """
    if member.is_dir():
        return materialize_directory
    if plain:
        return materialize_regular_file
    mode = entry_mode(member)
    if stat.S_ISLNK(mode):
        return materialize_symlink
    if mode and not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
        return materialize_special
    return materialize_regular_file


def _temporary_name(directory: str, dir_fd: int | None) -> str:
    name = f"{_TEMP_PREFIX}{secrets.token_hex(16)}"
    return name if dir_fd is not None else os.path.join(directory, name)


def publish_exclusive(temp: str, name: str, dir_fd: int | None) -> None:
    """Move *temp* to *name*, raising ``FileExistsError`` if *name* exists.

    A hard link is atomic and never exposes a partial file. Filesystems
    without hard links (FAT, exFAT, some network mounts) instead get an
    ``O_EXCL`` placeholder that is then replaced by *temp*: still no-clobber
    against files that already exist, but the empty placeholder is briefly
    visible, and a file swapped in over it during that instant is replaced.
    """
    try:
        os.link(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
    except FileExistsError:
        raise
    except OSError:
        placeholder = os.open(
            name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=dir_fd
        )
        os.close(placeholder)
        try:
            os.replace(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            with suppress(FileNotFoundError):
                os.unlink(name, dir_fd=dir_fd)
            raise


def _commit_temp(
    params: MaterializeParams, temp: str, name: str, dir_fd: int | None, size: int
) -> MaterializationResult:
    """Publish a complete entry; exclusive policies never replace a racing file."""
    if params.overwrite == OverwritePolicy.REPLACE:
        leaf = _lstat_leaf(name, dir_fd)
        if leaf is not None and stat.S_ISDIR(leaf.st_mode):
            raise ExtractionMaterializationError(
                "Refusing to replace an existing directory"
            )
        existed = leaf is not None
        os.replace(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        return MaterializationResult(Path(params.targetpath), size, existed)
    candidate = name
    counter = 0
    while True:
        target = Path(params.targetpath).with_name(os.path.basename(candidate))
        if candidate != name and params.quota.validate_target is not None:
            params.quota.validate_target(target)
        try:
            publish_exclusive(temp, candidate, dir_fd)
        except FileExistsError:
            if params.overwrite != OverwritePolicy.RENAME:
                raise
            counter += 1
            stem, suffix = os.path.splitext(name)
            candidate = f"{stem}.{counter}{suffix}"
        else:
            target = Path(params.targetpath).with_name(os.path.basename(candidate))
            return MaterializationResult(target, size)


def materialize_member(
    member: ZipInfo,
    targetpath: str,
    open_member: Callable[[], IO[bytes]],
    root: str,
    quota: ExtractionQuota | None = None,
    *,
    fsync: bool = True,
    reporter: ProgressReporter | None = None,
    overwrite: OverwritePolicy = OverwritePolicy.REPLACE,
    plain: bool = False,
) -> MaterializationResult:
    """Create the filesystem object for *member* at *targetpath* below *root*.

    Missing parent directories are created without following symlinks
    beneath *root*.  Regular files are fsynced before being moved into place
    unless *fsync* is ``False``.  *plain* is passed to
    :func:`select_materializer`.
    """
    parent = os.path.dirname(targetpath)
    dir_fd = (
        open_secure_parent(parent, root, quota.created_directories if quota else None)
        if parent
        else None
    )
    try:
        params = MaterializeParams(
            member,
            targetpath,
            open_member,
            quota or ExtractionQuota(),
            parent or ".",
            dir_fd,
            fsync,
            reporter,
            root,
            overwrite,
        )
        return select_materializer(member, plain=plain)(params)
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
