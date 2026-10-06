"""Opening archives."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from zipctl.cli.context import Context
from zipctl.cli.errors import CliError, os_error_text
from zipctl.cli.output import printable
from zipctl.exceptions import BadZipFile
from zipctl.limits import ArchiveResourceLimitError
from zipctl.zipfile.file import ZipFile

__all__ = ["open_archive", "opening"]


def open_archive(path: str, ctx: Context) -> ZipFile:
    with opening(path):
        return ZipFile(
            path, limits=ctx.limits, allow_prepended_data=ctx.allow_prepended_data
        )


@contextmanager
def opening(path: str) -> Generator[None]:
    """Report a failure to open the archive at *path* as a :class:`CliError`."""
    try:
        yield
    except ArchiveResourceLimitError as exc:
        raise CliError(
            f"{printable(path)}: archive resource limit exceeded ({exc})"
        ) from None
    except BadZipFile as exc:
        raise CliError(
            f"{printable(path)}: not a valid ZIP archive ({printable(str(exc))})"
        ) from None
    except NotImplementedError as exc:
        raise CliError(f"{printable(path)}: unsupported ZIP feature ({exc})") from None
    except OSError as exc:
        raise CliError(f"cannot open {printable(path)}: {os_error_text(exc)}") from None
