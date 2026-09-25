"""The ``check-password`` command."""

from __future__ import annotations

import argparse
from typing import Any

from ziplet.cli.archive import open_archive
from ziplet.cli.commands.helpers.command import add_command
from ziplet.cli.commands.helpers.output_options import add_output_options
from ziplet.cli.commands.helpers.passwords.options import (
    PasswordOptions,
    add_password_options,
    single_password,
)
from ziplet.cli.commands.helpers.selection import MEMBER_HELP, select_infos
from ziplet.cli.context import Context
from ziplet.cli.errors import EXIT_FAILURE, EXIT_OK, CliError
from ziplet.cli.output import count, printable, write_json
from ziplet.exceptions import BadZipFile
from ziplet.zipfile.file import ZipFile
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.password import (
    MemberPasswordCheck,
    PasswordCheckResult,
    PasswordStatus,
)

_LINES = {
    PasswordStatus.ACCEPTED: ("OK", ""),
    PasswordStatus.REJECTED: ("FAILED", ": password does not match"),
    PasswordStatus.CORRUPT: ("FAILED", ": password matches but the data is corrupt"),
    PasswordStatus.UNENCRYPTED: ("SKIP", ": not encrypted"),
}


def _summary(encrypted: int, accepted: int, full: bool) -> str:
    if not encrypted:
        return "No encrypted members to check"
    text = f"Checked {count(encrypted, 'encrypted member')}: "
    text += "all OK" if accepted == encrypted else f"{encrypted - accepted} failed"
    if accepted and not full:
        text += " (verifier only; use --full to authenticate the data)"
    return text


def _check(
    zf: ZipFile, infos: list[ZipInfo], args: argparse.Namespace, ctx: Context
) -> PasswordCheckResult:
    if not any(info.is_encrypted for info in infos):
        # Nothing to unlock, so do not ask for (or insist on) a password.
        plain = PasswordStatus.UNENCRYPTED
        return PasswordCheckResult(
            tuple(MemberPasswordCheck(info.filename, plain) for info in infos)
        )
    password = single_password(PasswordOptions.from_args(args), ctx)
    try:
        return zf.check_password(password, members=infos, full=args.full)
    except (BadZipFile, NotImplementedError) as exc:
        raise CliError(f"cannot check the password: {printable(str(exc))}") from None


def cmd_check_password(args: argparse.Namespace, ctx: Context) -> int:
    with open_archive(args.archive) as zf:
        result = _check(zf, select_infos(zf.infolist(), args.members), args, ctx)

    checks = result.members
    encrypted = sum(check.status is not PasswordStatus.UNENCRYPTED for check in checks)
    accepted = len(result.accepted)
    if args.json:
        write_json(
            ctx.stdout,
            {
                "ok": result.ok,
                "archive": args.archive,
                "full": args.full,
                "encrypted": encrypted,
                "accepted": accepted,
                "rejected": len(result.rejected),
                "corrupt": len(result.corrupt),
                "members": [
                    {"name": check.member, "status": check.status.value}
                    for check in checks
                ],
            },
        )
    else:
        listed = False
        for check in checks:
            label, detail = _LINES[check.status]
            if check.status in (PasswordStatus.REJECTED, PasswordStatus.CORRUPT) or (
                args.verbose
            ):
                ctx.out(f"{label:<8}{printable(check.member)}{detail}")
                listed = True
        if listed:
            ctx.out()
        ctx.out(_summary(encrypted, accepted, args.full))
    return EXIT_OK if result.ok else EXIT_FAILURE


def register(subparsers: Any) -> None:
    parser = add_command(
        subparsers,
        "check-password",
        cmd_check_password,
        "check whether one password matches the encrypted members",
    )
    parser.add_argument(
        "archive",
        metavar="ARCHIVE",
        help="the encrypted archive to check the password against",
    )
    parser.add_argument(
        "members",
        nargs="*",
        metavar="MEMBER",
        help=MEMBER_HELP,
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="also authenticate each member's data (definitive, but reads the "
        "members). Default: check only the password verifier",
    )
    add_output_options(parser, verbose_help="also list members that match")
    add_password_options(parser)
