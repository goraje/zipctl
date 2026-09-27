"""The password options of the commands, and the passwords they resolve to."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from zipctl.cli.commands.helpers.passwords.pool import PasswordPool, build_password_pool
from zipctl.cli.commands.helpers.passwords.sources import (
    WAYS_TO_GIVE,
    password_bytes,
    prompt_password,
    require_tty_for_prompt,
    static_passwords,
)
from zipctl.cli.context import Context
from zipctl.cli.errors import UsageError


class PasswordArgs(Protocol):
    """What :func:`add_password_options` leaves on the parsed arguments."""

    password_file: str | None
    password_stdin: bool
    password_prompt: bool


class OldPasswordArgs(Protocol):
    """What :func:`add_old_password_options` leaves on the parsed arguments."""

    old_password_file: str | None
    old_password_stdin: bool


@dataclass(frozen=True)
class PasswordOptions:
    """The options of :func:`add_password_options`."""

    file: str | None
    stdin: bool
    prompt: bool

    @classmethod
    def from_args(cls, args: PasswordArgs) -> PasswordOptions:
        return cls(args.password_file, args.password_stdin, args.password_prompt)


def add_password_options(parser: argparse.ArgumentParser) -> None:
    """Add ``--password-prompt``, ``--password-stdin`` and ``--password-file``."""
    parser.add_argument(
        "--password-prompt",
        action="store_true",
        help="ask for passwords at the terminal",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="read one password from the first line of standard input",
    )
    parser.add_argument(
        "--password-file",
        metavar="FILE",
        help="read one password from the first line of FILE",
    )


def add_old_password_options(parser: argparse.ArgumentParser) -> None:
    """Options for the passwords that unlock the input of a rewrite."""
    parser.add_argument(
        "--old-password-stdin",
        action="store_true",
        help="read the input password from the first line of standard input",
    )
    parser.add_argument(
        "--old-password-file",
        metavar="FILE",
        help="read the input password from the first line of FILE",
    )


def old_password_pool(args: OldPasswordArgs, ctx: Context) -> PasswordPool:
    """A pool for the input side of a rewrite (see :func:`add_old_password_options`)."""
    return build_password_pool(
        ctx,
        file=args.old_password_file,
        stdin=args.old_password_stdin,
        prompt=False,
        old=True,
    )


def password_pool(options: PasswordOptions, ctx: Context) -> PasswordPool:
    """A pool for the options of :func:`add_password_options`."""
    return build_password_pool(
        ctx,
        file=options.file,
        stdin=options.stdin,
        prompt=options.prompt,
    )


def _given(options: PasswordOptions, ctx: Context) -> list[bytes]:
    """The passwords the options name (``--password-prompt`` skips the environment)."""
    return static_passwords(
        ctx, file=options.file, stdin=options.stdin, use_env=not options.prompt
    )


def _require_one(known: list[bytes], what: str) -> None:
    if len(known) > 1:
        raise UsageError(
            f"{what} one password; give --password-file or --password-stdin "
            "with a single value, not different ones",
        )


def single_password(
    options: PasswordOptions,
    ctx: Context,
    prompt: Callable[[str], str] = prompt_password,
) -> bytes:
    """The one password a command asks about: from a source, else prompted for."""
    known = _given(options, ctx)
    _require_one(known, "this command tests")
    if known:
        return known[0]
    if not ctx.stdin.isatty():
        if options.prompt:
            require_tty_for_prompt(ctx)
        raise UsageError(f"no password given ({WAYS_TO_GIVE})")
    text = prompt("Password: ")
    if not text:
        raise UsageError("no password entered")
    return password_bytes(text)


def given_password(options: PasswordOptions, ctx: Context) -> bytes | None:
    """The one password from a source (file, stdin, environment), if there is one."""
    known = _given(options, ctx)
    _require_one(known, "this command uses")
    return known[0] if known else None
