"""The ``encrypt`` command."""

from __future__ import annotations

from typing import Protocol

from ziplet.cli.archive import open_archive
from ziplet.cli.commands.helpers.command import Subparsers, add_command
from ziplet.cli.commands.helpers.copying.copy import run_copy
from ziplet.cli.commands.helpers.copying.options import (
    CopyArgs,
    add_copy_options,
    check_paths,
    copy_job,
)
from ziplet.cli.commands.helpers.copying.targets import PLAIN, target_for_method
from ziplet.cli.commands.helpers.encryption.options import (
    add_wz_aes_version,
    require_aes_for_version,
)
from ziplet.cli.commands.helpers.encryption.plan import warn_if_weak
from ziplet.cli.commands.helpers.passwords.options import (
    PasswordArgs,
    PasswordOptions,
    add_password_options,
    given_password,
)
from ziplet.cli.commands.helpers.passwords.sources import (
    prompt_new_password,
    require_tty_for_prompt,
)
from ziplet.cli.commands.helpers.selection import select
from ziplet.cli.context import Context
from ziplet.cli.errors import CliError
from ziplet.cli.methods import ENCRYPTABLE, ENCRYPTION_METHODS
from ziplet.cli.output import count, printable


class EncryptArgs(CopyArgs, PasswordArgs, Protocol):
    encryption: str
    match: list[str]
    wz_aes_version: int | None


def cmd_encrypt(args: EncryptArgs, ctx: Context) -> int:
    job = copy_job(args)
    passwords = PasswordOptions.from_args(args)
    check_paths(job)
    method = ENCRYPTION_METHODS[args.encryption]
    require_aes_for_version(args.wz_aes_version, [method])
    if passwords.prompt:
        require_tty_for_prompt(ctx)
    with open_archive(job.input) as src:
        infos = src.infolist()
        already = [info for info in infos if info.is_encrypted]
        if already:
            raise CliError(
                f"{count(len(already), 'member')} of {printable(job.input)} "
                f"already encrypted (first: {printable(already[0].filename)}); use "
                "'ziplet rewrite' to change how members are protected"
            )
        files = [info.filename for info in infos if not info.is_dir()]
        chosen = select(files, args.match, "file")
        if not chosen:
            raise CliError(f"{printable(job.input)} has no files to encrypt")
        password = given_password(passwords, ctx)
        if not job.report.quiet:
            warn_if_weak([method], ctx)
        if password is None:
            password = prompt_new_password("Password", ctx)
        target = target_for_method(method, password, args.wz_aes_version)
        targets = [
            target if not info.is_dir() and info.filename in chosen else PLAIN
            for info in infos
        ]
        return run_copy(ctx, src, [None] * len(infos), targets, job, verb="Encrypted")


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
    parser.add_argument(
        "--match",
        action="append",
        default=[],
        metavar="GLOB",
        help="Encrypt only members matching GLOB, leave the others plain. Repeatable",
    )
    add_wz_aes_version(parser)
    add_password_options(parser)
