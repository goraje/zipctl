"""Secure extraction-root primitives.

The descriptor-backed implementation is used on platforms exposing the
required POSIX APIs.  The path-based fallback remains available for Windows
and other platforms where ``dir_fd``/``O_NOFOLLOW`` are not consistently
provided by Python.
"""

from __future__ import annotations

import errno
import os
import stat
from contextlib import suppress
from pathlib import Path

from typing_extensions import Self

from zipctl.zipfile.exceptions import ExtractionSecurityError


class SecureExtractionRoot:
    """Create extraction parents without following existing symlink components.

    *path* is trusted and resolved once, here; see :func:`open_secure_parent`.
    """

    def __init__(self, path: Path) -> None:
        # Policy extraction hands over already-resolved targets, so paths are
        # matched against both the given and the resolved spelling.
        self._spellings: tuple[str, str] = (
            os.path.abspath(path),
            os.path.realpath(path),
        )
        self.path: Path = Path(self._spellings[1])
        self._descriptor: int | None = None

    @property
    def descriptor_supported(self) -> bool:
        return (
            os.name == "posix"
            and hasattr(os, "O_NOFOLLOW")
            and os.mkdir in os.supports_dir_fd
            and os.open in os.supports_dir_fd
        )

    def __enter__(self) -> Self:
        self.path.mkdir(parents=True, exist_ok=True)
        if self.descriptor_supported:
            self._descriptor = os.open(
                self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None

    def ensure_parents(self, relative_parts: tuple[str, ...]) -> int | None:
        """Create and validate parent directories for a relative member path.

        Where descriptor support exists, each component is created and opened
        relative to its parent descriptor with ``O_NOFOLLOW``, so no
        check-then-act window exists between validation and use. Returns an
        open descriptor for the final directory; the caller owns it and must
        close it. Returns ``None`` on the path-based fallback.
        """
        if self._descriptor is None:
            self._ensure_paths(relative_parts)
            return None
        fd = os.dup(self._descriptor)
        try:
            for part in relative_parts:
                _make_directory(part, fd)
                try:
                    child = os.open(
                        part,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=fd,
                    )
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise ExtractionSecurityError(
                            "Refusing to traverse unsafe extraction path"
                        ) from exc
                    raise
                os.close(fd)
                fd = child
        except BaseException:
            os.close(fd)
            raise
        return fd

    def open_parent(self, path: str) -> int | None:
        """Create *path* below the root, as :func:`open_secure_parent` does."""
        return self.ensure_parents(_parts_below(path, self._spellings))

    def _ensure_paths(self, parts: tuple[str, ...]) -> None:
        current = self.path
        for part in parts:
            current /= part
            if (
                current.is_symlink()
                or _is_reparse_point(current)
                or (current.exists() and not current.is_dir())
            ):
                raise ExtractionSecurityError(
                    "Refusing to traverse unsafe extraction path"
                )
            _make_directory(str(current), None)


def _is_reparse_point(path: Path) -> bool:
    """Junctions and other Windows reparse points are not ordinary parents."""
    if os.name != "nt":
        return False
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except FileNotFoundError:
        return False


def _make_directory(name: str, fd: int | None) -> None:
    with suppress(FileExistsError):
        os.mkdir(name, dir_fd=fd)


def _parts_below(path: str, roots: tuple[str, ...]) -> tuple[str, ...]:
    """Return *path*'s components below the first of *roots* it is under."""
    for candidate in roots:
        parts = tuple(
            part
            for part in os.path.relpath(path, candidate).split(os.sep)
            if part and part != os.curdir
        )
        if os.pardir not in parts:
            return parts
    raise ExtractionSecurityError("Refusing to extract outside the destination")


def open_secure_parent(path: str, root: str) -> int | None:
    """Create *path* below *root* without following symlinks beneath *root*.

    *root* is the caller's chosen destination and is trusted, so symlinks in
    its own path (``/tmp`` on macOS, a symlinked home directory) are resolved.
    Only components below it, which archive contents can influence, are
    refused when they are symlinks.

    Returns an open descriptor for the final directory where the platform
    supports ``dir_fd``-relative operations, ``None`` otherwise. The caller
    owns the descriptor and must close it, which keeps the guard alive
    through the caller's own leaf write.

    Raises:
        ExtractionSecurityError: If *path* is outside *root* or crosses a
            symlink or file.
    """
    with SecureExtractionRoot(Path(root)) as secure_root:
        return secure_root.open_parent(path)


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


def sync_directory(directory: str) -> None:
    """Make renames in *directory* durable; best effort (not every platform can)."""
    try:
        handle = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(handle)
        finally:
            os.close(handle)
    except OSError:
        pass
