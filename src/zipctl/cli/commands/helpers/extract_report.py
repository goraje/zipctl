"""What ``extract`` prints, as text or as JSON."""

from __future__ import annotations

import os

from zipctl.cli.commands.helpers.output_options import OutputOptions
from zipctl.cli.context import Context
from zipctl.cli.output import count, human_size, printable, write_json
from zipctl.zipfile.extract import (
    ExtractMemberResult,
    ExtractResult,
    MemberStatus,
    ViolationAction,
)

__all__ = ["report_extraction", "report_plain"]

_ARCHIVE_LEVEL = "<archive>"


def _reasons(member: ExtractMemberResult) -> str:
    """Why a member was skipped or failed, without the archive-wide findings."""
    messages = [
        violation.message
        for violation in member.violations
        if violation.member != _ARCHIVE_LEVEL
        and violation.action is not ViolationAction.WARN
    ]
    return "; ".join(printable(message) for message in messages)


def _render_violations(ctx: Context, result: ExtractResult, *, quiet: bool) -> bool:
    """Print archive-level errors and warnings; True if a line was listed."""
    listed = False
    for violation in result.violations:
        if violation.member == _ARCHIVE_LEVEL and violation.action is not (
            ViolationAction.WARN
        ):
            message = printable(violation.message)
            ctx.out(f"{'ERROR':<8}{_ARCHIVE_LEVEL}: {message} [{violation.code}]")
            listed = True
        elif violation.action is ViolationAction.WARN and not quiet:
            ctx.warn(f"{printable(violation.member)}: {printable(violation.message)}")
    return listed


def _render_members(ctx: Context, result: ExtractResult, output: OutputOptions) -> bool:
    """Print failed, skipped and (verbose) extracted members; True if any."""
    quiet = output.quiet
    listed = False
    for member in result.members:
        name = printable(member.member)
        if member.status in (MemberStatus.FAILED, MemberStatus.SKIPPED):
            reason = _reasons(member)
            if member.status is MemberStatus.FAILED and not reason:
                continue  # rejected as a whole; the archive line says why
            if member.status is MemberStatus.SKIPPED and quiet:
                continue
            label = "FAILED" if member.status is MemberStatus.FAILED else "SKIP"
            ctx.out(f"{label:<8}{name}: {reason}" if reason else f"{label:<8}{name}")
            listed = True
        elif output.verbose and not quiet:
            verb = "Would extract" if result.preview_only else "Extracting"
            ctx.out(f"{verb}: {name}")
            listed = True
    return listed


def _render_summary(ctx: Context, destination: str, result: ExtractResult) -> None:
    extra: list[str] = []
    if result.skipped_count:
        extra.append(f"{result.skipped_count} skipped")
    if result.failed_count:
        extra.append(f"{result.failed_count} failed")
    tail = "".join(f", {item}" for item in extra)
    target = printable(destination)
    if result.preview_only:
        would = count(result.previewed_count, "member")
        ctx.out(f"Dry run: would extract to {target}: {would}{tail}")
    elif not result.extracted_count and result.failed_count:
        ctx.out(f"Nothing extracted{tail}")  # the destination may not exist
    else:
        done = count(result.extracted_count, "member")
        size = human_size(result.bytes_written)
        ctx.out(f"Extracted to {target}: {done} ({size}){tail}")


def _render_text(
    ctx: Context,
    destination: str,
    result: ExtractResult,
    output: OutputOptions,
) -> None:
    listed = _render_violations(ctx, result, quiet=output.quiet)
    listed = _render_members(ctx, result, output) or listed
    if output.quiet:
        return
    if listed or ctx.warned:
        ctx.out()
    _render_summary(ctx, destination, result)


def report_plain(
    ctx: Context,
    archive: str,
    destination: str,
    extracted: int,
    output: OutputOptions,
) -> None:
    """The report of an extraction with no policy: it either worked or raised."""
    if output.json:
        write_json(
            ctx.stdout,
            {
                "ok": True,
                "archive": archive,
                "destination": os.path.abspath(destination),
                "policy": False,
                "extracted": extracted,
            },
        )
    elif not output.quiet:
        if ctx.warned:
            ctx.out()
        ctx.out(f"Extracted to {printable(destination)}: {count(extracted, 'member')}")


def report_extraction(
    ctx: Context,
    archive: str,
    destination: str,
    result: ExtractResult,
    output: OutputOptions,
) -> None:
    """The report of an extraction that ran under a policy."""
    if output.json:
        write_json(
            ctx.stdout,
            {
                "ok": result.failed_count == 0,
                "archive": archive,
                "destination": os.path.abspath(destination),
                "policy": True,
                "dry_run": result.preview_only,
                "result": result,
            },
        )
    else:
        _render_text(ctx, destination, result, output)
