"""The ``extract`` command."""

from __future__ import annotations

import os
import warnings
from collections.abc import Callable
from dataclasses import replace
from typing import Protocol

from zipctl.cli.archive import open_archive
from zipctl.cli.commands.helpers.command import Subparsers, add_command
from zipctl.cli.commands.helpers.extract_report import report_extraction, report_plain
from zipctl.cli.commands.helpers.output_options import (
    OutputArgs,
    OutputOptions,
    add_output_options,
)
from zipctl.cli.commands.helpers.passwords.options import (
    PasswordArgs,
    PasswordOptions,
    add_password_options,
    password_pool,
)
from zipctl.cli.commands.helpers.passwords.pool import PasswordPool, PasswordProblem
from zipctl.cli.commands.helpers.policy_options import (
    PolicyArgs,
    add_policy_options,
    load_policy,
)
from zipctl.cli.commands.helpers.progress import (
    ProgressArgs,
    ProgressRenderer,
    add_progress_option,
    progress_renderer,
)
from zipctl.cli.commands.helpers.selection import MEMBER_HELP, select_infos
from zipctl.cli.context import Context
from zipctl.cli.errors import (
    EXIT_FAILURE,
    EXIT_OK,
    CliError,
    UsageError,
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


class ExtractArgs(OutputArgs, PasswordArgs, PolicyArgs, ProgressArgs, Protocol):
    archive: str
    members: list[str]
    match: list[str]
    destination: str | None
    no_policy: bool
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


def _reject_conflicting_options(args: ExtractArgs) -> None:
    if not args.no_policy:
        return
    used = [
        flag
        for flag, value in (
            ("--policy", args.policy),
            ("--policy-json", args.policy_json),
            ("--dry-run", args.dry_run),
            ("--overwrite", args.overwrite),
            ("--no-fsync", args.no_fsync),
        )
        if value not in (None, False)
    ]
    if used:
        raise UsageError(
            f"--no-policy cannot be combined with {', '.join(used)}; those options "
            "configure the policy that --no-policy turns off",
        )


def _password_provider(
    pool: PasswordPool, zf: ZipFile, renderer: ProgressRenderer | None
) -> Callable[[ZipInfo], bytes | None]:
    """A ``pwd=`` callable that finds (or asks for) each member's password."""

    def provide(info: ZipInfo) -> bytes | None:
        if renderer is not None:
            renderer.clear()  # keep a prompt from colliding with the status line
        resolved = pool.resolve(zf, info)
        if not isinstance(resolved, PasswordProblem):
            return resolved
        if resolved is PasswordProblem.CORRUPT:
            raise BadZipFile(resolved.text)
        if resolved is PasswordProblem.WRONG:
            raise BadPassword(resolved.text)
        raise PasswordRequired(resolved.text)

    return provide


def _run_extraction(
    zf: ZipFile,
    ctx: Context,
    pool: PasswordPool,
    policy: ExtractPolicy | None,
    members: list[ZipInfo] | None,
    destination: str,
    *,
    progress: bool,
    quiet: bool,
) -> ExtractResult | None:
    """Extract; the result is ``None`` for a plain (no policy) extraction."""
    result = None
    with (
        progress_renderer(ctx.stderr, progress) as renderer,
        warnings.catch_warnings(record=True) as caught,
    ):
        warnings.simplefilter("always")
        provider = _password_provider(pool, zf, renderer)
        try:
            if policy is None:
                zf.extractall(
                    destination, members=members, pwd=provider, progress=renderer
                )
            else:
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
    reported: set[str] = {v.message for v in result.violations} if result else set()
    for warning in caught:
        text = str(warning.message)
        if text not in reported and not quiet:
            ctx.warn(printable(text))
    return result


def cmd_extract(args: ExtractArgs, ctx: Context) -> int:
    _reject_conflicting_options(args)
    output = OutputOptions.from_args(args)
    policy = None if args.no_policy else _extraction_policy(args, ctx)
    destination = args.destination or os.getcwd()
    with open_archive(args.archive, ctx) as zf:
        patterns = [*args.members, *args.match]
        members = select_infos(zf.infolist(), patterns) if patterns else None
        pool = password_pool(PasswordOptions.from_args(args), ctx)
        result = _run_extraction(
            zf,
            ctx,
            pool,
            policy,
            members,
            destination,
            progress=args.progress,
            quiet=output.quiet,
        )
        extracted = len(members) if members is not None else len(zf.infolist())
    if result is None:
        report_plain(ctx, args.archive, destination, extracted, output)
        return EXIT_OK
    report_extraction(
        ctx,
        args.archive,
        destination,
        result,
        output,
    )
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
    parser.add_argument(
        "--match",
        action="append",
        default=[],
        metavar="GLOB",
        help="same as a MEMBER pattern (repeatable); a pattern that matches "
        "nothing is an error",
    )
    parser.add_argument(
        "-d",
        "--destination",
        metavar="DIR",
        help="directory to extract into. Default: the current directory",
    )
    parser.add_argument(
        "--no-policy",
        action="store_true",
        help="extract like Python's zipfile: no limits or rules, links and special "
        "files written as regular files (path traversal is still neutralised)",
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
