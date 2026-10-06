"""The ``inspect`` command."""

from __future__ import annotations

import os
from typing import Protocol

from zipctl.cli.archive import open_archive
from zipctl.cli.commands.helpers.command import Subparsers, add_command
from zipctl.cli.commands.helpers.output_options import add_output_options
from zipctl.cli.commands.helpers.policy_options import (
    PolicyArgs,
    add_policy_options,
    load_policy,
)
from zipctl.cli.context import Context
from zipctl.cli.errors import EXIT_FAILURE, EXIT_OK
from zipctl.cli.output import (
    Output,
    count,
    human_size,
    printable,
)
from zipctl.cli.reports import (
    Inspection,
    InspectMember,
    InspectReport,
    violation_json,
)
from zipctl.zipfile.inspection import InspectionMember, InspectionResult
from zipctl.zipfile.policy import (
    ViolationAction,
)


class InspectArgs(PolicyArgs, Protocol):
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
    output: Output,
    archive: str,
    destination: str,
    result: InspectionResult,
    errors: int,
) -> None:
    if output.quiet:
        if errors:  # the details alone: no verdict, as when nothing is wrong
            output.problem("Details:")
            for line in _violations(result):
                output.problem(line)
        return
    verdict = "OK" if not errors else f"FAILED ({count(errors, 'error')})"
    directories = sum(1 for member in result.members if member.is_directory)
    flagged = {violation.member for violation in result.violations}
    output.line(f"Archive:      {printable(archive)}")
    output.line(f"Destination:  {printable(destination)}")
    output.line(
        f"Members:      {result.total_entries} "
        f"({count(directories, 'directory', 'directories')})"
    )
    output.line(
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
    ]
    output.line(f"Result:       {verdict}")
    if details:
        output.line()
        output.line("Details:")
        for line in details:
            output.line(line)


def _member_json(member: InspectionMember) -> InspectMember:
    return {
        "member": member.member,
        "target": None if member.target is None else str(member.target),
        "is_directory": member.is_directory,
        "compressed_size": member.compressed_size,
        "uncompressed_size": member.uncompressed_size,
        "compression_ratio": member.compression_ratio,
        "encrypted": member.encrypted,
        "is_symlink": member.is_symlink,
        "is_special_file": member.is_special_file,
        "violations": [violation_json(v) for v in member.violations],
        "assessed": member.assessed,
    }


def _inspection_json(result: InspectionResult) -> Inspection:
    """The ``inspection`` object of ``inspect --json``: a fixed CLI contract, built
    field by field so library changes cannot reshape it."""
    return {
        "total_entries": result.total_entries,
        "total_compressed_size": result.total_compressed_size,
        "total_uncompressed_size": result.total_uncompressed_size,
        "members": [_member_json(member) for member in result.members],
        "duplicate_targets": [str(target) for target in result.duplicate_targets],
        "suspicious_paths": list(result.suspicious_paths),
        "encrypted_members": list(result.encrypted_members),
        "large_members": list(result.large_members),
        "compress_ratio_outliers": list(result.compress_ratio_outliers),
        "symlinks": list(result.symlinks),
        "special_files": list(result.special_files),
        "warnings": [violation_json(v) for v in result.warnings],
        "violations": [violation_json(v) for v in result.violations],
        "member_count_over_limit": result.member_count_over_limit,
    }


def cmd_inspect(args: InspectArgs, ctx: Context) -> int:
    policy = load_policy(args, ctx)
    destination = os.path.abspath(args.destination or os.getcwd())
    with open_archive(args.archive, ctx) as zf:
        result = zf.inspect(destination, policy)
    errors = sum(v.action is ViolationAction.ERROR for v in result.violations)
    if ctx.output.json:
        report: InspectReport = {
            "ok": errors == 0,
            "archive": args.archive,
            "destination": destination,
            "inspection": _inspection_json(result),
        }
        ctx.output.document(report)
    else:
        _render_inspection(ctx.output, args.archive, destination, result, errors)
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
