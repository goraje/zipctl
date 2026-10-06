"""The ``decrypt`` command."""

from __future__ import annotations

from typing import Protocol

from zipctl.cli.commands.helpers.command import Subparsers, add_command
from zipctl.cli.commands.helpers.copy import (
    CopyArgs,
    Intent,
    add_copy_options,
    open_copy,
)
from zipctl.cli.commands.helpers.passwords import (
    PasswordArgs,
    PasswordFamily,
    add_password_options,
)
from zipctl.cli.commands.helpers.selection import add_match_option, select
from zipctl.cli.context import Context
from zipctl.cli.errors import CliError
from zipctl.cli.output import printable


class DecryptArgs(CopyArgs, PasswordArgs, Protocol):
    match: list[str]


def cmd_decrypt(args: DecryptArgs, ctx: Context) -> int:
    with open_copy(args, ctx) as copy:
        encrypted = [info.filename for info in copy.infos if info.is_encrypted]
        if not encrypted:
            raise CliError(f"{printable(args.input)} has no encrypted members")
        chosen = select(encrypted, args.match, "encrypted member")
        pool = PasswordFamily.from_args(args).pool(ctx)
        return copy.run(
            lambda info: (
                Intent.PLAIN
                if not info.is_encrypted or info.filename in chosen
                else Intent.KEEP
            ),
            verb="Decrypted",
            pool=pool,
        )


def register(subparsers: Subparsers) -> None:
    parser = add_command(
        subparsers,
        "decrypt",
        cmd_decrypt,
        "copy an encrypted archive into a new, unencrypted one",
    )
    add_copy_options(parser)
    add_match_option(
        parser,
        "Decrypt only members matching GLOB, leave the others encrypted. Repeatable",
    )
    add_password_options(parser)
