"""Command-line interface: ``zipctl`` and ``python -m zipctl``."""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from collections.abc import Sequence

from zipctl.cli.commands.helpers.command import Handler
from zipctl.cli.context import Context
from zipctl.cli.errors import (
    EXIT_BROKEN_PIPE,
    EXIT_FAILURE,
    EXIT_INTERRUPTED,
    EXIT_OK,
    CliError,
    os_error_filename,
    os_error_text,
)
from zipctl.cli.output import printable, write_json
from zipctl.cli.parser import build_parser
from zipctl.cli.streams import normalize_output
from zipctl.limits import ArchiveResourceLimitError

__all__ = ["main"]


class _Parsed(argparse.Namespace):
    """The parsed arguments, with the handler the chosen command registered."""

    handler: Handler  # pyright: ignore[reportUninitializedInstanceVariable]  # set by argparse


def _exit_code(code: object) -> int:
    if code is None:
        return EXIT_OK
    return code if isinstance(code, int) else 1


def _quiet_broken_pipe() -> None:
    """Stop Python complaining again about the closed pipe when it exits."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, sys.stdout.fileno())
        finally:
            os.close(devnull)
    except (OSError, ValueError):
        pass


def _fail(
    ctx: Context,
    args: argparse.Namespace,
    exc: Exception,
    message: str,
    code: int,
    details: tuple[str, ...] = (),
) -> int:
    """Report *message* on standard error (and as JSON with ``--json``)."""
    if ctx.environ.get("ZIPCTL_DEBUG"):
        exc.__suppress_context__ = False  # show the error a ``from None`` hid
        traceback.print_exception(exc, file=ctx.stderr)
    ctx.err(f"zipctl: error: {message}")
    for line in details:
        ctx.err(f"  {line}")
    wants_json: bool = getattr(args, "json", False)  # not every command has --json
    if wants_json:
        error = {"ok": False, "error": message, "code": code, "details": list(details)}
        write_json(ctx.stdout, error)
    return code


def _configure_streams(ctx: Context) -> None:
    for stream in (ctx.stdout, ctx.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI with *argv* (default: ``sys.argv[1:]``); return the exit code."""
    ctx = Context.from_process()
    _configure_streams(ctx)
    ctx.stdout = normalize_output(ctx.stdout)
    try:
        return _run(argv, ctx)
    except BrokenPipeError:
        _quiet_broken_pipe()
        return EXIT_BROKEN_PIPE


def _run(argv: Sequence[str] | None, ctx: Context) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(
            sys.argv[1:] if argv is None else argv, namespace=_Parsed()
        )
    except SystemExit as exc:
        return _exit_code(exc.code)

    try:
        code = args.handler(args, ctx)
        ctx.stdout.flush()
        return int(code)
    except CliError as exc:
        return _fail(ctx, args, exc, exc.message, exc.code, exc.details)
    except ArchiveResourceLimitError as exc:
        return _fail(ctx, args, exc, printable(str(exc)), EXIT_FAILURE)
    except KeyboardInterrupt:
        ctx.err("zipctl: interrupted")
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        raise
    except OSError as exc:  # whatever a command did not translate itself
        filename = os_error_filename(exc)
        where = f"{printable(filename)}: " if filename else ""
        message = f"{where}{printable(os_error_text(exc))}"
        return _fail(ctx, args, exc, message, EXIT_FAILURE)
    except Exception as exc:  # a bug: name it, and offer the traceback
        message = f"unexpected {type(exc).__name__}: {printable(str(exc))}"
        if not ctx.environ.get("ZIPCTL_DEBUG"):
            message += " (set ZIPCTL_DEBUG=1 for the traceback)"
        return _fail(ctx, args, exc, message, EXIT_FAILURE)
