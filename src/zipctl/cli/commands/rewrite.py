"""The ``rewrite`` command."""

from __future__ import annotations

from typing import Protocol

from zipctl.cli.archive import open_archive
from zipctl.cli.commands.helpers.command import Subparsers, add_command
from zipctl.cli.commands.helpers.copying.copy import read_passwords, run_copy
from zipctl.cli.commands.helpers.copying.options import (
    CopyArgs,
    add_copy_options,
    check_paths,
    copy_job,
)
from zipctl.cli.commands.helpers.copying.targets import (
    PLAIN,
    Target,
    keep_target,
    target_for_method,
)
from zipctl.cli.commands.helpers.encryption.options import (
    EncryptionArgs,
    EncryptionOptions,
    add_encryption_options,
    build_plan,
)
from zipctl.cli.commands.helpers.encryption.plan import warn_if_weak
from zipctl.cli.commands.helpers.passwords.options import (
    OldPasswordArgs,
    add_old_password_options,
    add_password_options,
    old_password_pool,
)
from zipctl.cli.context import Context
from zipctl.cli.errors import UsageError
from zipctl.cli.methods import COMPRESSION, require_compression, require_level


class RewriteArgs(CopyArgs, EncryptionArgs, OldPasswordArgs, Protocol):
    compression: str | None
    level: int | None


def cmd_rewrite(args: RewriteArgs, ctx: Context) -> int:
    job = copy_job(args)
    check_paths(job)
    if args.compression is not None:
        require_compression(args.compression)
        require_level(args.compression, args.level)
    elif args.level is not None:
        raise UsageError("--level needs --compression")
    encryption = EncryptionOptions.from_args(args)
    plan = build_plan(encryption, ctx)
    with open_archive(job.input, ctx) as src:
        infos = src.infolist()
        assignment = plan.assign([info.filename for info in infos if not info.is_dir()])
        if not job.report.quiet:
            warn_if_weak(assignment.methods, ctx)
        old_pool = old_password_pool(args, ctx)
        passwords = read_passwords(src, infos, old_pool)
        plan.resolve_prompts(assignment, ctx)
        targets: list[Target] = []
        for info, password in zip(infos, passwords, strict=True):
            if info.is_dir():
                targets.append(PLAIN)
            elif rule := assignment.chosen.get(info.filename):
                targets.append(
                    target_for_method(
                        rule.method, rule.password, encryption.wz_aes_version
                    )
                )
            else:
                targets.append(keep_target(info, password))
        return run_copy(
            ctx,
            src,
            passwords,
            targets,
            job,
            verb="Rewrote",
            compress_type=None
            if args.compression is None
            else COMPRESSION[args.compression],
            level=args.level,
        )


def register(subparsers: Subparsers) -> None:
    parser = add_command(
        subparsers,
        "rewrite",
        cmd_rewrite,
        "copy an archive into a new one, changing its encryption or compression",
    )
    add_copy_options(parser)
    parser.add_argument(
        "--compression",
        metavar="METHOD",
        choices=list(COMPRESSION),
        help=f"Compression method for every member: {', '.join(COMPRESSION)}. "
        "Default: each member keeps its own",
    )
    parser.add_argument(
        "-L",
        "--level",
        type=int,
        metavar="N",
        help="Compression level. Needs --compression",
    )
    add_encryption_options(parser)
    add_old_password_options(parser)
    add_password_options(parser)
