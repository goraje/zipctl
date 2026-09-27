"""The ``inspect`` command."""

from __future__ import annotations

import os
from typing import Protocol

from ziplet.cli.archive import open_archive
from ziplet.cli.commands.helpers.command import Subparsers, add_command
from ziplet.cli.commands.helpers.output_options import OutputArgs, add_output_options
from ziplet.cli.commands.helpers.policy_options import (
    PolicyArgs,
    add_policy_options,
    load_policy,
)
from ziplet.cli.context import Context
from ziplet.cli.errors import EXIT_FAILURE, EXIT_OK
from ziplet.cli.output import (
    count,
    human_size,
    printable,
    write_json,
)
from ziplet.zipfile.extract import (
    ViolationAction,
)
from ziplet.zipfile.inspection import InspectionResult


class InspectArgs(OutputArgs, PolicyArgs, Protocol):
    archive: str
    destination: str | None


def _section(title: str, names: tuple[str, ...], flagged: set[str]) -> list[str]:
    """A titled list of *names*, leaving out those a violation already reports."""
    names = tuple(name for name in names if name not in flagged)
    if not names:
        return []
    return [f"  {title} ({len(names)}):", *(f"    {printable(name)}" for name in names)]


def _violations(result: InspectionResult) -> list[str]:
    if not result.violations:
        return []
    return [
        f"  Violations ({len(result.violations)}):",
        *(
            f"    {violation.action.value.upper():<7}{printable(violation.member)}: "
            f"{printable(violation.message)}"
            for violation in result.violations
        ),
    ]


def _render_inspection(
    ctx: Context,
    archive: str,
    destination: str,
    result: InspectionResult,
    errors: int,
    quiet: bool,
) -> None:
    if quiet:
        if errors:  # the details alone: no verdict, as when nothing is wrong
            ctx.out("Details:")
            for line in _violations(result):
                ctx.out(line)
        return
    verdict = "OK" if not errors else f"FAILED ({count(errors, 'error')})"
    directories = sum(1 for member in result.members if member.is_directory)
    flagged = {violation.member for violation in result.violations}
    ctx.out(f"Archive:      {printable(archive)}")
    ctx.out(f"Destination:  {printable(destination)}")
    ctx.out(
        f"Members:      {result.total_entries} "
        f"({count(directories, 'directory', 'directories')})"
    )
    ctx.out(
        f"Size:         {human_size(result.total_uncompressed_size)} "
        f"({human_size(result.total_compressed_size)} compressed)"
    )
    details = [
        *_violations(result),
        *_section("Encrypted members", result.encrypted_members, flagged),
        *_section("Suspicious paths", result.suspicious_paths, flagged),
        *_section("Symlinks", result.symlinks, flagged),
        *_section("Special files", result.special_files, flagged),
        *_section("Large members", result.large_members, flagged),
        *_section("Ratio outliers", result.compress_ratio_outliers, flagged),
        *_section("Duplicate names", result.duplicate_member_names, flagged),
    ]
    ctx.out(f"Result:       {verdict}")
    if details:
        ctx.out("")
        ctx.out("Details:")
        for line in details:
            ctx.out(line)


def cmd_inspect(args: InspectArgs, ctx: Context) -> int:
    policy = load_policy(args, ctx)
    destination = os.path.abspath(args.destination or os.getcwd())
    with open_archive(args.archive) as zf:
        result = zf.inspect(destination, policy)
    errors = sum(v.action is ViolationAction.ERROR for v in result.violations)
    if args.json:
        write_json(
            ctx.stdout,
            {
                "ok": errors == 0,
                "archive": args.archive,
                "destination": destination,
                "inspection": result,
            },
        )
    else:
        _render_inspection(
            ctx,
            args.archive,
            destination,
            result,
            errors,
            args.quiet,
        )
    return EXIT_FAILURE if errors else EXIT_OK


def register(subparsers: Subparsers) -> None:
    parser = add_command(
        subparsers,
        "inspect",
        cmd_inspect,
        "report what extracting would flag, without reading any data",
    )
    parser.add_argument("archive", metavar="ARCHIVE", help="the archive to inspect")
    parser.add_argument(
        "-d",
        "--destination",
        metavar="DIR",
        help="directory the members would be extracted into, used to detect "
        "overwrites. Default: the current directory",
    )
    add_output_options(parser, quiet=True)
    add_policy_options(parser)
