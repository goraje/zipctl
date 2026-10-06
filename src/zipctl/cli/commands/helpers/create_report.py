"""What ``create`` prints, as text or as JSON."""

from __future__ import annotations

from zipctl.cli.methods import NO_ENCRYPTION
from zipctl.cli.output import Output, count, human_size, printable
from zipctl.cli.reports import (
    CreatedMember,
    CreateReport,
    DryRunReport,
    PlannedMember,
    SkippedPath,
)

__all__ = ["report_created", "report_dry_run"]


def _detail(member: CreatedMember | PlannedMember) -> str:
    """What a listing says about *member*: its kind, compression and protection."""
    if member["directory"]:
        return "directory"
    plain = member["encryption"] == NO_ENCRYPTION.label
    if member["is_symlink"]:
        return "symlink" if plain else f"symlink, {member['encryption']}"
    return f"{member['compression']}, {member['encryption']}"


def _warn_skipped(
    output: Output, skipped: list[tuple[str, str]], unused: list[str]
) -> None:
    for path, reason in skipped:
        output.warn(f"skipping {printable(path)}: {reason}")
    for pattern in unused:
        output.warn(f"--exclude {printable(pattern)!r} matched nothing")


def _skipped_json(skipped: list[tuple[str, str]]) -> list[SkippedPath]:
    return [{"path": p, "reason": r} for p, r in skipped]


def report_dry_run(
    output: Output,
    archive: str,
    members: list[PlannedMember],
    skipped: list[tuple[str, str]],
    unused: list[str],
    *,
    appending: bool,
) -> None:
    files = sum(not m["directory"] for m in members)
    directories = len(members) - files
    if output.json:
        report: DryRunReport = {
            "ok": True,
            "archive": archive,
            "dry_run": True,
            "appended": appending,
            "file_count": files,
            "directory_count": directories,
            "members": members,
            "skipped": _skipped_json(skipped),
            "unused_excludes": unused,
        }
        output.document(report)
        return
    _warn_skipped(output, skipped, unused)
    for member in members:
        output.line(f"Would add: {printable(member['name'])} ({_detail(member)})")
    parts = f"{count(files, 'file')}, {count(directories, 'directory', 'directories')}"
    name = printable(archive)
    verb = f"add to {name}" if appending else f"create {name}"
    output.summary(f"Dry run: would {verb}: {parts}")


def report_created(
    output: Output,
    archive: str,
    members: list[CreatedMember],
    skipped: list[tuple[str, str]],
    unused: list[str],
    *,
    appended: bool,
) -> None:
    files = [m for m in members if not m["directory"]]
    directories = len(members) - len(files)
    original = sum(m["size"] for m in files)
    stored = sum(m["compressed_size"] for m in files)
    if output.json:
        report: CreateReport = {
            "ok": True,
            "archive": archive,
            "appended": appended,
            "file_count": len(files),
            "directory_count": directories,
            "bytes_in": original,
            "bytes_out": stored,
            "members": members,
            "skipped": _skipped_json(skipped),
            "unused_excludes": unused,
        }
        output.document(report)
        return
    _warn_skipped(output, skipped, unused)
    for member in members:
        output.detail(f"Adding: {printable(member['name'])} ({_detail(member)})")
    encrypted = sum(m["encryption"] != NO_ENCRYPTION.label for m in files)
    parts = [count(len(files), "file"), count(directories, "directory", "directories")]
    if encrypted:
        parts.append(f"{encrypted} encrypted")
    size = f"{human_size(original)}, {human_size(stored)} compressed"
    name = printable(archive)
    if appended:
        output.summary(f"Added {', '.join(parts)} ({size}) to {name}")
    else:
        output.summary(f"Created {name}: {', '.join(parts)} ({size})")
