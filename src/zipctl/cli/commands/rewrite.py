"""The ``rewrite`` command."""

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
    EncryptionArgs,
    EncryptionOptions,
    add_encryption_options,
    build_plan,
)
from zipctl.cli.commands.helpers.passwords import (
    OldPasswordArgs,
    PasswordFamily,
    add_old_password_options,
    add_password_options,
)
from zipctl.cli.context import Context
from zipctl.cli.errors import UsageError
from zipctl.cli.methods import (
    COMPRESSION,
    add_compression_options,
    require_compression,
    require_level,
)
from zipctl.zipfile.info import ZipInfo


class RewriteArgs(CopyArgs, EncryptionArgs, OldPasswordArgs, Protocol):
    compression: str | None
    level: int | None


def cmd_rewrite(args: RewriteArgs, ctx: Context) -> int:
    if args.compression is not None:
        require_compression(args.compression)
        require_level(args.compression, args.level)
    elif args.level is not None:
        raise UsageError("--level needs --compression")
    plan = build_plan(EncryptionOptions.from_args(args), ctx)
    with open_copy(args, ctx) as copy:
        names = [info.filename for info in copy.infos if not info.is_dir()]
        assignment = plan.assign(names, ctx)
        old_pool = PasswordFamily.old_from_args(args).pool(ctx)
        # A member whose protection and compression are left as they are is
        # copied as stored and needs no password.
        recompress = args.compression is not None

        def intent(info: ZipInfo) -> Intent:
            if assignment.chosen.get(info.filename):
                return Intent.NEW
            return Intent.SAME if recompress else Intent.KEEP

        return copy.run(
            intent,
            verb="Rewrote",
            pool=old_pool,
            protect=lambda info: assignment.protection(info.filename, ctx),
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
    add_compression_options(
        parser,
        default=None,
        default_text="each member keeps its own (--level needs --compression)",
    )
    add_encryption_options(parser)
    add_old_password_options(parser)
    add_password_options(parser)
