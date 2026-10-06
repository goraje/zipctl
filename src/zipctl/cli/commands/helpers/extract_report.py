"""What ``extract`` prints, as text or as JSON."""

from __future__ import annotations

import os

from zipctl.cli.output import Output, count, human_size, printable
from zipctl.cli.reports import ExtractReport, violation_json
from zipctl.cli.reports import ExtractResult as ResultReport
from zipctl.zipfile.policy import (
    ExtractMemberResult,
    ExtractResult,
    MemberStatus,
    ViolationAction,
)

__all__ = ["report_extraction"]

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


def _render_violations(output: Output, result: ExtractResult) -> None:
    """Print archive-level errors and warnings."""
    for violation in result.violations:
        if violation.member == _ARCHIVE_LEVEL and violation.action is not (
            ViolationAction.WARN
        ):
            message = printable(violation.message)
            output.problem(
                f"{'ERROR':<8}{_ARCHIVE_LEVEL}: {message} [{violation.code}]"
            )
        elif violation.action is ViolationAction.WARN:
            output.warn(
                f"{printable(violation.member)}: {printable(violation.message)}"
            )


def _render_members(output: Output, result: ExtractResult) -> None:
    """Print failed, skipped and (verbose) extracted members."""
    for member in result.members:
        name = printable(member.member)
        if member.status in (MemberStatus.FAILED, MemberStatus.SKIPPED):
            reason = _reasons(member)
            if member.status is MemberStatus.FAILED and not reason:
                continue  # rejected as a whole; the archive line says why
            label = "FAILED" if member.status is MemberStatus.FAILED else "SKIP"
            line = f"{label:<8}{name}: {reason}" if reason else f"{label:<8}{name}"
            if member.status is MemberStatus.FAILED:
                output.problem(line)
            else:
                output.line(line)
        else:
            verb = "Would extract" if result.preview_only else "Extracting"
            output.detail(f"{verb}: {name}")


def _summary(destination: str, result: ExtractResult) -> str:
    extra: list[str] = []
    if result.skipped_count:
        extra.append(f"{result.skipped_count} skipped")
    if result.failed_count:
        extra.append(f"{result.failed_count} failed")
    tail = "".join(f", {item}" for item in extra)
    target = printable(destination)
    if result.preview_only:
        would = count(result.previewed_count, "member")
        return f"Dry run: would extract to {target}: {would}{tail}"
    if not result.extracted_count and result.failed_count:
        return f"Nothing extracted{tail}"  # the destination may not exist
    done = count(result.extracted_count, "member")
    size = human_size(result.bytes_written)
    return f"Extracted to {target}: {done} ({size}){tail}"


def report_extraction(
    output: Output,
    archive: str,
    destination: str,
    result: ExtractResult,
) -> None:
    """The report of an extraction that ran under a policy."""
    if output.json:
        report: ExtractReport = {
            "ok": result.failed_count == 0,
            "archive": archive,
            "destination": os.path.abspath(destination),
            "policy": True,
            "dry_run": result.preview_only,
            "result": _result_json(result),
        }
        output.document(report)
        return
    _render_violations(output, result)
    _render_members(output, result)
    output.summary(_summary(destination, result))


def _result_json(result: ExtractResult) -> ResultReport:
    """The ``result`` object of ``extract --json``: a fixed CLI contract, built
    field by field so library changes cannot reshape it."""
    return {
        "destination": str(result.destination),
        "members": [
            {
                "member": member.member,
                "status": member.status.value,
                "target": None if member.target is None else str(member.target),
                "is_directory": member.is_directory,
                "compressed_size": member.compressed_size,
                "uncompressed_size": member.uncompressed_size,
                "compression_ratio": member.compression_ratio,
                "bytes_written": member.bytes_written,
                "violations": [violation_json(v) for v in member.violations],
                "overwritten": member.overwritten,
            }
            for member in result.members
        ],
        "violations": [violation_json(v) for v in result.violations],
        "extracted_count": result.extracted_count,
        "skipped_count": result.skipped_count,
        "failed_count": result.failed_count,
        "bytes_written": result.bytes_written,
        "preview_only": result.preview_only,
        "previewed_count": result.previewed_count,
    }
