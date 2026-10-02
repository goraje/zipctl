"""Opening archives."""

from __future__ import annotations

from zipctl.cli.errors import CliError, os_error_text
from zipctl.cli.limits import current_limits
from zipctl.cli.output import printable
from zipctl.exceptions import BadZipFile
from zipctl.limits import ArchiveResourceLimitError
from zipctl.zipfile.file import ZipFile

__all__ = ["CHUNK", "open_archive"]

CHUNK = 1 << 20  # bytes read at a time when streaming a member


def open_archive(path: str) -> ZipFile:
    try:
        return ZipFile(path, limits=current_limits.get())
    except ArchiveResourceLimitError as exc:
        raise CliError(
            f"{printable(path)}: archive resource limit exceeded ({exc})"
        ) from None
    except BadZipFile:
        raise CliError(f"{printable(path)}: not a valid ZIP archive") from None
    except NotImplementedError as exc:
        raise CliError(f"{printable(path)}: unsupported ZIP feature ({exc})") from None
    except OSError as exc:
        raise CliError(f"cannot open {printable(path)}: {os_error_text(exc)}") from None
