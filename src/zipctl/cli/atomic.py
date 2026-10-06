"""Writing an archive so that a failed run leaves nothing behind."""

from __future__ import annotations

import os
import secrets
import shutil
import stat
from collections.abc import Generator
from contextlib import contextmanager, suppress

from zipctl.cli.errors import CliError, os_error_text
from zipctl.cli.output import printable
from zipctl.zipfile.secure_fs import publish_exclusive, sync_directory

__all__ = ["replacing"]


def _resulting_mode(target: str | None, source: str | None, default: int) -> int:
    """Permission bits for the result: the target's, narrowed by the source's.

    Without a target, *default* (what the umask gives a new file) applies.
    """
    mode = default if target is None else stat.S_IMODE(os.stat(target).st_mode)
    if source:
        mode &= stat.S_IMODE(os.stat(source).st_mode)
    return mode


def _owned_by_someone_else(path: str) -> bool:
    """Whether the link at *path* was planted by another user (POSIX only)."""
    getuid = getattr(os, "getuid", None)
    return getuid is not None and os.lstat(path).st_uid not in (getuid(), 0)


def _create_private(scratch: str, path: str) -> int:
    """Create *scratch* readable only by us; return the mode a new file would get.

    It is private while written, as it may hold decrypted data; the final mode
    is applied last.  If anything fails once it exists, it is removed again.
    """
    try:
        # 0o666 here: the kernel applies the umask, without touching ours
        handle = os.open(scratch, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
    except OSError as exc:
        raise CliError(
            f"cannot create {printable(path)}: {os_error_text(exc)}"
        ) from None
    try:
        try:
            mode = stat.S_IMODE(os.fstat(handle).st_mode)
            os.chmod(scratch, 0o600)
        finally:
            os.close(handle)
    except BaseException:
        with suppress(OSError):  # closed first: Windows cannot unlink an open file
            os.unlink(scratch)
        raise
    return mode


@contextmanager
def replacing(
    path: str, *, overwrite: bool, seed: bool = False, mode_from: str | None = None
) -> Generator[str]:
    """Yield a scratch path beside *path*; move it onto *path* if the block succeeds.

    The scratch file is removed if the block raises (Ctrl-C included), so *path*
    is either untouched or complete.  An existing *path* keeps its permission
    bits; with *mode_from* (the archive being copied) the result is never more
    permissive than that file either.  The bits are applied only once the
    block is done, so a read-only *path* can still be replaced.  With *seed*,
    the scratch file starts as a copy of it (for appending).  Unless
    *overwrite*, an existing *path* is refused, both up front and again just
    before the move.
    """
    if os.path.islink(path) and _owned_by_someone_else(path):
        raise CliError(f"{printable(path)} is a symbolic link owned by another user")
    target = os.path.realpath(path)  # through a symlink, so the link survives
    exists = os.path.lexists(target)
    if exists and not overwrite:
        raise CliError(f"{printable(path)} already exists (use --force to replace it)")
    directory = os.path.dirname(target)
    scratch = os.path.join(directory, f".zipctl-{secrets.token_hex(8)}.tmp")
    default_mode = _create_private(scratch, path)
    try:
        if seed and exists:
            shutil.copyfile(target, scratch)
        mode = _resulting_mode(target if exists else None, mode_from, default_mode)
        yield scratch
        with open(scratch, "rb+") as written:  # still writable: fsync needs that
            os.fsync(written.fileno())  # on Windows
        os.chmod(scratch, mode)  # a 0600 archive stays 0600
        try:
            if overwrite:
                os.replace(scratch, target)
            else:
                publish_exclusive(scratch, target, None)
                with suppress(FileNotFoundError):  # gone if it was moved, not linked
                    os.unlink(scratch)
        except FileExistsError:
            raise CliError(f"{printable(path)} already exists") from None
        except OSError as exc:
            raise CliError(
                f"cannot replace {printable(path)}: {os_error_text(exc)}"
            ) from None
        sync_directory(directory)
    except BaseException:
        with suppress(OSError):  # never created, or out of reach: keep the error
            os.unlink(scratch)
        raise
