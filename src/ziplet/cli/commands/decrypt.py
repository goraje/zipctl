"""The ``decrypt`` command."""

from __future__ import annotations

import argparse
from typing import Any

from ziplet.cli.archive import open_archive
from ziplet.cli.commands.helpers.command import add_command
from ziplet.cli.commands.helpers.copying.copy import read_passwords, run_copy
from ziplet.cli.commands.helpers.copying.options import (
    add_copy_options,
    check_paths,
    copy_job,
)
from ziplet.cli.commands.helpers.copying.targets import PLAIN, keep_target
from ziplet.cli.commands.helpers.passwords.options import (
    PasswordOptions,
    add_password_options,
    password_pool,
)
from ziplet.cli.commands.helpers.selection import select
from ziplet.cli.context import Context
from ziplet.cli.errors import CliError
from ziplet.cli.output import printable


def cmd_decrypt(args: argparse.Namespace, ctx: Context) -> int:
    job = copy_job(args)
    check_paths(job)
    with open_archive(job.input) as src:
        infos = src.infolist()
        encrypted = [info.filename for info in infos if info.is_encrypted]
        if not encrypted:
            raise CliError(f"{printable(job.input)} has no encrypted members")
        chosen = select(encrypted, args.match, "encrypted member")
        passwords = read_passwords(
            src, infos, password_pool(PasswordOptions.from_args(args), ctx)
        )
        targets = [
            PLAIN
            if not info.is_encrypted or info.filename in chosen
            else keep_target(info, password)
            for info, password in zip(infos, passwords, strict=True)
        ]
        return run_copy(ctx, src, passwords, targets, job, verb="Decrypted")


def register(subparsers: Any) -> None:
    parser = add_command(
        subparsers,
        "decrypt",
        cmd_decrypt,
        "copy an encrypted archive into a new, unencrypted one",
    )
    add_copy_options(parser)
    parser.add_argument(
        "--match",
        action="append",
        default=[],
        metavar="GLOB",
        help="Decrypt only members matching GLOB, leave the others encrypted. "
        "Repeatable",
    )
    add_password_options(parser)
