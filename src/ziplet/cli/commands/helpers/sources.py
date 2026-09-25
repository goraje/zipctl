"""Reading text that a command line option names by file or standard input."""

from __future__ import annotations

from pathlib import Path

from ziplet.cli.context import Context
from ziplet.cli.errors import UsageError, os_error_text
from ziplet.cli.output import printable

__all__ = ["read_text_source"]


def read_text_source(source: str, ctx: Context, what: str) -> str:
    """The UTF-8 text of file *source* (``-`` is standard input), BOM removed.

    *what* names the file in messages, e.g. ``"policy file"``.
    """
    if source == "-":
        named = f"the {what} on standard input"
        ctx.claim_stdin(f"the {what}")
        data = ctx.read_stdin()
    else:
        named = f"{what} {printable(source)}"
        try:
            data = Path(source).read_bytes()
        except OSError as exc:
            raise UsageError(f"cannot read {named}: {os_error_text(exc)}") from None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise UsageError(f"{named} is not valid UTF-8") from None
