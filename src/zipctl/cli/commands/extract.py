"""The ``extract`` command."""

from __future__ import annotations

import os
import warnings
from collections.abc import Callable
from dataclasses import replace
from typing import Protocol

from zipctl.cli.archive import open_archive
from zipctl.cli.commands.helpers.command import Subparsers, add_command
from zipctl.cli.commands.helpers.extract_report import report_extraction
from zipctl.cli.commands.helpers.output_options import add_output_options
from zipctl.cli.commands.helpers.passwords import (
    PasswordArgs,
    PasswordFamily,
    PasswordPool,
    PasswordProblem,
    add_password_options,
)
from zipctl.cli.commands.helpers.policy_options import (
    PolicyArgs,
    add_policy_options,
    load_policy,
)
from zipctl.cli.commands.helpers.progress import (
    ProgressArgs,
    add_progress_option,
    progress_renderer,
)
from zipctl.cli.commands.helpers.selection import (
    MEMBER_HELP,
    add_match_option,
    select_infos,
)
from zipctl.cli.context import Context
from zipctl.cli.errors import (
    EXIT_FAILURE,
    EXIT_OK,
    CliError,
    os_error_text,
)
from zipctl.cli.output import printable
from zipctl.exceptions import BadPassword, BadZipFile, PasswordError, PasswordRequired
from zipctl.zipfile.exceptions import ExtractionFailure
from zipctl.zipfile.file import ZipFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.policy import (
    ExtractionError,
    ExtractPolicy,
    ExtractResult,
    OverwritePolicy,
)


class ExtractArgs(PasswordArgs, PolicyArgs, ProgressArgs, Protocol):
    archive: str
    members: list[str]
    match: list[str]
    destination: str | None
    dry_run: bool
    overwrite: str | None
    no_fsync: bool


def _extraction_policy(args: ExtractArgs, ctx: Context) -> ExtractPolicy:
    policy = load_policy(args, ctx)
    if args.overwrite is not None:
        policy = replace(policy, overwrite_policy=OverwritePolicy(args.overwrite))
    if args.no_fsync:
        policy = replace(policy, fsync_files=False)
    if args.dry_run:
        policy = replace(policy, preview_only=True)
    return policy


def _password_provider(
    pool: PasswordPool, zf: ZipFile
) -> Callable[[ZipInfo], bytes | None]:
    """A ``pwd=`` callable that finds (or asks for) each member's password."""

    def provide(info: ZipInfo) -> bytes | None:
        resolved = pool.resolve(zf, info)
        if not isinstance(resolved, PasswordProblem):
            return resolved
        if resolved is PasswordProblem.CORRUPT:
            raise BadZipFile(pool.explain(resolved))
        if resolved is PasswordProblem.WRONG:
            raise BadPassword(pool.explain(resolved))
        raise PasswordRequired(pool.explain(resolved))

    return provide


def _run_extraction(
    zf: ZipFile,
    ctx: Context,
    pool: PasswordPool,
    policy: ExtractPolicy,
    members: list[ZipInfo] | None,
    destination: str,
    *,
    progress: bool,
) -> ExtractResult:
    """Extract under *policy* and return its result."""
    with (
        progress_renderer(ctx.output, progress) as renderer,
        warnings.catch_warnings(record=True) as caught,
    ):
        warnings.simplefilter("always")
        provider = _password_provider(pool, zf)
        try:
            result = zf.safe_extractall(
                destination,
                members=members,
                pwd=provider,
                policy=policy,
                progress=renderer,
            )
        except ExtractionError as exc:
            result = exc.result
        except (
            ExtractionFailure,
            PasswordError,
            BadZipFile,
            NotImplementedError,
        ) as exc:
            raise CliError(f"cannot extract: {printable(str(exc))}") from None
        except OSError as exc:
            raise CliError(f"cannot extract: {printable(os_error_text(exc))}") from None
    # A policy violation is reported with the result; anything else is news.
    reported: set[str] = {v.message for v in result.violations}
    for warning in caught:
        text = str(warning.message)
        if text not in reported:
            ctx.output.warn(printable(text))
    return result


def cmd_extract(args: ExtractArgs, ctx: Context) -> int:
    policy = _extraction_policy(args, ctx)
    destination = args.destination or os.getcwd()
    if os.path.lexists(destination) and not os.path.isdir(destination):
        raise CliError(f"{printable(destination)} exists and is not a directory")
    with open_archive(args.archive, ctx) as zf:
        patterns = [*args.members, *args.match]
        members = select_infos(zf.infolist(), patterns) if patterns else None
        pool = PasswordFamily.from_args(args).pool(ctx)
        result = _run_extraction(
            zf,
            ctx,
            pool,
            policy,
            members,
            destination,
            progress=args.progress,
        )
    report_extraction(ctx.output, args.archive, destination, result)
    return EXIT_FAILURE if result.failed_count > 0 else EXIT_OK


def register(subparsers: Subparsers) -> None:
    parser = add_command(
        subparsers,
        "extract",
        cmd_extract,
        "extract members, enforcing an extraction policy",
    )
    parser.add_argument(
        "archive", metavar="ARCHIVE", help="the archive to extract from"
    )
    parser.add_argument(
        "members",
        nargs="*",
        metavar="MEMBER",
        help=MEMBER_HELP,
    )
    add_match_option(
        parser,
        "same as a MEMBER pattern (repeatable); a pattern that matches nothing is "
        "an error",
    )
    parser.add_argument(
        "-d",
        "--destination",
        metavar="DIR",
        help="directory to extract into. Default: the current directory",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="assess every member and report, writing nothing",
    )
    parser.add_argument(
        "--overwrite",
        choices=[choice.value for choice in OverwritePolicy],
        metavar="MODE",
        help="what to do when a target already exists: error, skip, replace or "
        "rename. Default: error",
    )
    parser.add_argument(
        "--no-fsync",
        action="store_true",
        help="do not fsync each file (faster, but less durable)",
    )
    add_progress_option(parser)
    add_output_options(parser, verbose_help="list every member", quiet=True)
    add_policy_options(parser)
    add_password_options(parser)
