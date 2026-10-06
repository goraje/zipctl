"""The ``encrypt`` command."""

from __future__ import annotations

from typing import Protocol

from zipctl.cli.commands.helpers.command import Subparsers, add_command
from zipctl.cli.commands.helpers.copy import (
    CopyArgs,
    Intent,
    add_copy_options,
    open_copy,
)
from zipctl.cli.commands.helpers.encryption_options import (
    add_wz_aes_version,
    one_method_plan,
)
from zipctl.cli.commands.helpers.passwords import (
    PasswordArgs,
    PasswordFamily,
    add_password_options,
)
from zipctl.cli.commands.helpers.selection import add_match_option, select
from zipctl.cli.context import Context
from zipctl.cli.errors import CliError
from zipctl.cli.methods import ENCRYPTABLE, ENCRYPTION_METHODS
from zipctl.cli.output import count, printable


class EncryptArgs(CopyArgs, PasswordArgs, Protocol):
    encryption: str
    match: list[str]
    wz_aes_version: int | None


def cmd_encrypt(args: EncryptArgs, ctx: Context) -> int:
    method = ENCRYPTION_METHODS[args.encryption]
    with open_copy(args, ctx) as copy:
        already = [info for info in copy.infos if info.is_encrypted]
        if already:
            raise CliError(
                f"{count(len(already), 'member')} of {printable(args.input)} "
                f"already encrypted (first: {printable(already[0].filename)}); use "
                "'zipctl rewrite' to change how members are protected"
            )
        files = [info.filename for info in copy.infos if not info.is_dir()]
        # --match is a union, as in every other command, so overlapping globs are
        # fine; plan rules are ordered and refuse a rule that decides nothing.
        chosen = select(files, args.match, "file")
        if not chosen:
            raise CliError(f"{printable(args.input)} has no files to encrypt")
        passwords = PasswordFamily.from_args(args)
        plan = one_method_plan(method, passwords, ctx, args.wz_aes_version)
        assignment = plan.assign(sorted(chosen), ctx)
        return copy.run(
            lambda info: Intent.NEW if info.filename in chosen else Intent.PLAIN,
            verb="Encrypted",
            protect=lambda info: assignment.protection(info.filename, ctx),
        )


def register(subparsers: Subparsers) -> None:
    parser = add_command(
        subparsers,
        "encrypt",
        cmd_encrypt,
        "copy an unencrypted archive into a new, encrypted one",
    )
    add_copy_options(parser)
    parser.add_argument(
        "--encryption",
        choices=ENCRYPTABLE,
        default="aes256",
        metavar="METHOD",
        help=f"Encryption method: {', '.join(ENCRYPTABLE)}. Default: aes256",
    )
    add_match_option(
        parser, "Encrypt only members matching GLOB, leave the others plain. Repeatable"
    )
    add_wz_aes_version(parser)
    add_password_options(parser)
