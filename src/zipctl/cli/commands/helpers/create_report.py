"""What ``create`` prints, as text or as JSON."""

from __future__ import annotations

from dataclasses import dataclass

from zipctl.cli.commands.helpers.output_options import OutputOptions
from zipctl.cli.context import Context
from zipctl.cli.methods import NO_ENCRYPTION
from zipctl.cli.output import JsonValue, count, human_size, printable, write_json

__all__ = ["Added", "Planned", "report_created", "report_dry_run"]


@dataclass(frozen=True)
class Added:
    """A member as written to the archive."""

    name: str
    directory: bool
    is_symlink: bool
    size: int
    compressed_size: int
    compression: str | None
    encryption: str


@dataclass(frozen=True)
class Planned:
    """A member ``--dry-run`` says would be written; *encryption* is a label."""

    name: str
    directory: bool
    is_symlink: bool
    compression: str | None
    encryption: str


def _detail(member: Added | Planned) -> str:
    """What a listing says about *member*: its kind, compression and protection."""
    if member.directory:
        return "directory"
    plain = member.encryption == NO_ENCRYPTION.label
    if member.is_symlink:
        return "symlink" if plain else f"symlink, {member.encryption}"
    return f"{member.compression}, {member.encryption}"


def _warn_skipped(
    ctx: Context, skipped: list[tuple[str, str]], unused: list[str]
) -> None:
    for path, reason in skipped:
        ctx.warn(f"skipping {printable(path)}: {reason}")
    for pattern in unused:
        ctx.warn(f"--exclude {printable(pattern)!r} matched nothing")


def _skipped_json(
    skipped: list[tuple[str, str]], unused: list[str]
) -> dict[str, JsonValue]:
    return {
        "skipped": [{"path": p, "reason": r} for p, r in skipped],
        "unused_excludes": unused,
    }


def report_dry_run(
    ctx: Context,
    archive: str,
    members: list[Planned],
    skipped: list[tuple[str, str]],
    unused: list[str],
    *,
    appending: bool,
    output: OutputOptions,
) -> None:
    files = sum(not m.directory for m in members)
    directories = len(members) - files
    if output.json:
        write_json(
            ctx.stdout,
            {
                "ok": True,
                "archive": archive,
                "dry_run": True,
                "appended": appending,
                "file_count": files,
                "directory_count": directories,
                "members": members,
                **_skipped_json(skipped, unused),
            },
        )
        return
    if output.quiet:
        return
    _warn_skipped(ctx, skipped, unused)
    for member in members:
        ctx.out(f"Would add: {printable(member.name)} ({_detail(member)})")
    if members or ctx.warned:
        ctx.out()
    parts = f"{count(files, 'file')}, {count(directories, 'directory', 'directories')}"
    name = printable(archive)
    verb = f"add to {name}" if appending else f"create {name}"
    ctx.out(f"Dry run: would {verb}: {parts}")


def report_created(
    ctx: Context,
    archive: str,
    members: list[Added],
    skipped: list[tuple[str, str]],
    unused: list[str],
    *,
    appended: bool,
    output: OutputOptions,
) -> None:
    files = [m for m in members if not m.directory]
    directories = len(members) - len(files)
    original = sum(m.size for m in files)
    stored = sum(m.compressed_size for m in files)
    if output.json:
        write_json(
            ctx.stdout,
            {
                "ok": True,
                "archive": archive,
                "appended": appended,
                "file_count": len(files),
                "directory_count": directories,
                "bytes_in": original,
                "bytes_out": stored,
                "members": members,
                **_skipped_json(skipped, unused),
            },
        )
        return
    if output.quiet:
        return
    _warn_skipped(ctx, skipped, unused)
    if output.verbose:
        for member in members:
            ctx.out(f"Adding: {printable(member.name)} ({_detail(member)})")
    if ctx.warned or (output.verbose and members):
        ctx.out()
    encrypted = sum(m.encryption != NO_ENCRYPTION.label for m in files)
    parts = [count(len(files), "file"), count(directories, "directory", "directories")]
    if encrypted:
        parts.append(f"{encrypted} encrypted")
    size = f"{human_size(original)}, {human_size(stored)} compressed"
    name = printable(archive)
    if appended:
        ctx.out(f"Added {', '.join(parts)} ({size}) to {name}")
    else:
        ctx.out(f"Created {name}: {', '.join(parts)} ({size})")
