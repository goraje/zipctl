"""Writing an archive so that a failed run leaves nothing behind."""

from __future__ import annotations

import os
import secrets
import shutil
from collections.abc import Generator
from contextlib import contextmanager

from zipctl.cli.errors import CliError, os_error_text
from zipctl.cli.output import printable

__all__ = ["replacing"]


def _sync_directory(directory: str) -> None:
    """Make the rename durable; best effort (not every platform can do it)."""
    try:
        handle = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(handle)
        finally:
            os.close(handle)
    except OSError:
        pass


@contextmanager
def replacing(path: str, *, overwrite: bool, seed: bool = False) -> Generator[str]:
    """Yield a scratch path beside *path*; move it onto *path* if the block succeeds.

    The scratch file is removed if the block raises (Ctrl-C included), so *path*
    is either untouched or complete.  An existing *path* keeps its permission
    bits.  With *seed*, the scratch file starts as a copy of it (for
    appending).  Unless *overwrite*, an
    existing *path* is refused, both up front and again just before the move.
    """
    target = os.path.realpath(path)  # through a symlink, so the link survives
    exists = os.path.lexists(target)
    if exists and not overwrite:
        raise CliError(f"{printable(path)} already exists (use --force to replace it)")
    directory = os.path.dirname(target)
    scratch = os.path.join(directory, f".zipctl-{secrets.token_hex(8)}.tmp")
    try:
        # 0o666 here: the kernel applies the umask, without touching ours
        handle = os.open(scratch, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
    except OSError as exc:
        raise CliError(
            f"cannot create {printable(path)}: {os_error_text(exc)}"
        ) from None
    os.close(handle)
    try:
        if seed and exists:
            shutil.copyfile(target, scratch)
        if exists:
            shutil.copymode(target, scratch)  # a 0600 archive stays 0600
        yield scratch
        with open(scratch, "rb+") as written:
            os.fsync(written.fileno())
        # ponytail: check-then-replace, so a file created in this instant is
        # replaced; os.link would be exclusive but is not portable.
        if not overwrite and os.path.lexists(target):
            raise CliError(f"{printable(path)} already exists")
        try:
            os.replace(scratch, target)
        except OSError as exc:
            raise CliError(
                f"cannot replace {printable(path)}: {os_error_text(exc)}"
            ) from None
        _sync_directory(directory)
    except BaseException:
        try:
            os.unlink(scratch)
        except FileNotFoundError:
            pass
        raise
