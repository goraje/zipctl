"""The ``create`` command."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from typing import Protocol

from zipctl.cli.archive import open_archive, opening
from zipctl.cli.atomic import replacing
from zipctl.cli.commands.helpers.collect import Collector, Entry
from zipctl.cli.commands.helpers.command import Subparsers, add_command
from zipctl.cli.commands.helpers.create_report import report_created, report_dry_run
from zipctl.cli.commands.helpers.encryption_options import (
    EncryptionArgs,
    EncryptionOptions,
    add_encryption_options,
    build_plan,
)
from zipctl.cli.commands.helpers.encryption_plan import (
    UNPROTECTED,
    PlanAssignment,
    Protection,
)
from zipctl.cli.commands.helpers.output_options import add_output_options
from zipctl.cli.commands.helpers.passwords import add_password_options
from zipctl.cli.commands.helpers.progress import (
    ProgressArgs,
    ProgressRenderer,
    StepReporter,
    add_progress_option,
    progress_renderer,
)
from zipctl.cli.context import Context
from zipctl.cli.errors import EXIT_OK, CliError, UsageError, os_error_text
from zipctl.cli.methods import (
    COMPRESSION,
    NO_ENCRYPTION,
    add_compression_options,
    compression_label,
    method_of,
    require_compression,
    require_level,
)
from zipctl.cli.output import printable
from zipctl.cli.reports import CreatedMember, PlannedMember
from zipctl.limits import ArchiveLimits
from zipctl.zipfile.file import ZipFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.records import comment_forges_end_record
from zipctl.zipfile.shared import ZIP_MAX_COMMENT


class CreateArgs(EncryptionArgs, ProgressArgs, Protocol):
    archive: str
    paths: list[str]
    chdir: str | None
    exclude: list[str]
    symlinks: str
    dry_run: bool
    force: bool
    append: bool
    compression: str
    level: int | None
    comment: str | None


def _check_options(args: CreateArgs) -> bytes | None:
    """Refuse bad options; the ``--comment`` comes back encoded."""
    if args.chdir is not None and not os.path.isdir(args.chdir):
        raise UsageError(f"-C: {printable(args.chdir)} is not a directory")
    comment = None
    if args.comment is not None:
        try:
            comment = args.comment.encode("utf-8")
        except UnicodeEncodeError:
            raise UsageError("--comment is not valid UTF-8") from None
        if len(comment) > ZIP_MAX_COMMENT:
            raise UsageError("--comment is too long (65535 bytes at most)")
        if comment_forges_end_record(comment):
            raise UsageError("--comment contains an end of central directory record")
    require_compression(args.compression)
    require_level(args.compression, args.level)
    return comment


def _describe(zf: ZipFile, first: int) -> list[CreatedMember]:
    return [
        {
            "name": info.filename,
            "directory": info.is_dir(),
            "is_symlink": info.is_symlink(),
            "size": info.file_size,
            "compressed_size": info.compress_size,
            "compression": None if info.is_dir() else compression_label(info),
            "encryption": method_of(info).label,
        }
        for info in zf.infolist()[first:]
    ]


def _check_target(
    args: CreateArgs, entries: list[Entry], ctx: Context
) -> tuple[bool, list[Entry]]:
    """Refuse an archive that may not be written.

    Returns whether it is appended to, and the entries still to add: a
    directory the archive already holds is not added again, but a file with
    a name it already holds is refused.
    """
    exists = os.path.lexists(args.archive)
    if exists and not (args.force or args.append):
        raise CliError(
            f"{printable(args.archive)} already exists (use --force to replace it "
            "or --append to add to it)"
        )
    if not (args.append and exists):
        return False, entries
    with open_archive(args.archive, ctx) as existing:
        present = existing.NameToInfo
        clashes = [e.arcname for e in entries if not e.is_dir and e.arcname in present]
        new = [e for e in entries if e.arcname not in present]
    if clashes:
        listed = ", ".join(f"'{printable(name)}'" for name in clashes[:5])
        more = f" and {len(clashes) - 5} more" if len(clashes) > 5 else ""
        raise CliError(f"already in the archive: {listed}{more}")
    return True, new


@dataclass(frozen=True)
class CreateJob:
    """What ``create`` writes and how; *protections* covers files, not directories."""

    archive: str
    entries: list[Entry]
    protections: dict[str, Protection]
    appending: bool
    overwrite: bool
    compression: int
    level: int | None
    comment: bytes | None
    limits: ArchiveLimits
    allow_prepended_data: bool = False


def _write_archive(
    job: CreateJob, renderer: ProgressRenderer | None
) -> list[CreatedMember]:
    """Write the entries (into a copy, moved into place at the end)."""
    with replacing(job.archive, overwrite=job.overwrite, seed=job.appending) as scratch:
        with opening(job.archive):  # it may have changed since it was checked
            zf = ZipFile(
                scratch,
                "a" if job.appending else "w",
                compression=job.compression,
                compresslevel=job.level,
                strict_timestamps=False,
                limits=job.limits,
                allow_prepended_data=job.allow_prepended_data,
            )
        with zf:
            first = len(zf.infolist())
            if job.comment is not None:
                zf.comment = job.comment
            _add_all(zf, job.entries, job.protections, renderer)
            return _describe(zf, first)


def _size(entry: Entry) -> int:
    try:
        return os.path.getsize(entry.source) if _has_content(entry) else 0
    except OSError:
        return 0  # a vanished file fails in _add_entry, with a proper message


def _add_all(
    zf: ZipFile,
    entries: list[Entry],
    protections: dict[str, Protection],
    renderer: ProgressRenderer | None,
) -> None:
    steps = StepReporter(renderer, ((e.arcname, _size(e)) for e in entries))
    for index, entry in enumerate(entries):
        steps.start(index)
        try:
            _add_entry(zf, entry, protections.get(entry.arcname, UNPROTECTED))
        except CliError:
            steps.finish(index, ok=False)
            raise
        steps.finish(index, ok=True)


def cmd_create(args: CreateArgs, ctx: Context) -> int:
    comment = _check_options(args)
    encryption = EncryptionOptions.from_args(args)
    plan = build_plan(encryption, ctx)
    collector = Collector(args.chdir, args.archive, args.exclude, args.symlinks)
    for given in args.paths:
        collector.add_path(given)
    for link, target in collector.escaping:
        ctx.output.warn(
            f"{printable(link)} is a symbolic link to {printable(target)}, "
            "outside the directory being added; its content is stored "
            "(--symlinks store keeps the link instead)"
        )
    appending, entries = _check_target(args, collector.entries, ctx)

    files = [e.arcname for e in entries if not e.is_dir]
    assignment = plan.assign(files, ctx)
    unused = collector.unused_excludes()
    if args.dry_run:
        planned = _preview(entries, assignment, args.compression)
        report_dry_run(
            ctx.output,
            args.archive,
            planned,
            collector.skipped,
            unused,
            appending=appending,
        )
        return EXIT_OK
    job = CreateJob(
        args.archive,
        entries,
        {name: assignment.protection(name, ctx) for name in files},
        appending=appending,
        overwrite=args.force or args.append,
        compression=COMPRESSION[args.compression],
        level=args.level,
        comment=comment,
        limits=ctx.limits,
        allow_prepended_data=ctx.allow_prepended_data,
    )
    with progress_renderer(ctx.output, args.progress) as renderer:
        members = _write_archive(job, renderer)
    report_created(
        ctx.output,
        args.archive,
        members,
        collector.skipped,
        unused,
        appended=appending,
    )
    return EXIT_OK


def _has_content(entry: Entry) -> bool:
    """Whether *entry* holds file data to read from disk (not a directory or link)."""
    return not entry.is_dir and entry.link_target is None


def _add_link(
    zf: ZipFile, entry: Entry, link_target: str, protection: Protection
) -> None:
    """Store the link itself: its target is the entry's data, stored, not squeezed.

    The target is encrypted like any file's data, so a protected archive does
    not give away where its links point.
    """
    info = ZipInfo.from_file(
        entry.source, entry.arcname, strict_timestamps=False, follow_symlinks=False
    )
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    info.compress_type = COMPRESSION["store"]
    zf.writestr(
        info,
        link_target,
        encryption=protection.method.scheme,
        password=protection.password,
        extra=protection.extra,
    )


def _add_entry(zf: ZipFile, entry: Entry, protection: Protection) -> None:
    try:
        if entry.link_target is not None:
            _add_link(zf, entry, entry.link_target, protection)
            return
        if entry.is_dir:
            zf.write(entry.source, entry.arcname)
            return
        zf.write(
            entry.source,
            entry.arcname,
            encryption=protection.method.scheme,
            password=protection.password,
            extra=protection.extra,
        )
    except (OSError, ValueError, UnicodeError, RuntimeError) as exc:
        reason = os_error_text(exc) if isinstance(exc, OSError) else str(exc)
        raise CliError(
            f"cannot add {printable(entry.source)}: {printable(reason)}"
        ) from None


def _preview(
    entries: list[Entry], assignment: PlanAssignment, compression: str
) -> list[PlannedMember]:
    """What ``--dry-run`` would add: name, kind and protection of each entry."""
    planned: list[PlannedMember] = []
    for entry in entries:
        rule = assignment.chosen.get(entry.arcname)
        method = rule.method if rule else NO_ENCRYPTION
        link = entry.link_target is not None
        planned.append(
            {
                "name": entry.arcname,
                "directory": entry.is_dir,
                "is_symlink": link,
                "compression": None
                if entry.is_dir
                else "store"
                if link
                else compression,
                "encryption": method.label,
            }
        )
    return planned


def register(subparsers: Subparsers) -> None:
    parser = add_command(
        subparsers,
        "create",
        cmd_create,
        "create an archive from files and directories, optionally encrypted",
    )
    parser.add_argument("archive", metavar="ARCHIVE", help="the archive to create")
    parser.add_argument(
        "paths",
        nargs="+",
        metavar="PATH",
        help="files and directories to add",
    )
    parser.add_argument(
        "-C",
        "--directory",
        dest="chdir",
        metavar="DIR",
        help="take PATHs relative to DIR",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="leave out what matches GLOB. Repeatable",
    )
    parser.add_argument(
        "--symlinks",
        choices=["follow", "store", "skip"],
        default="follow",
        metavar="MODE",
        help=(
            "what to do with symbolic links: follow (store a link to a file as "
            "its content; links to directories are skipped), store or skip. "
            "Default: follow"
        ),
    )
    add_progress_option(parser)
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="list what would be added and write nothing",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--force", action="store_true", help="replace ARCHIVE if it exists"
    )
    mode.add_argument(
        "--append",
        action="store_true",
        help="add to ARCHIVE if it exists",
    )
    add_compression_options(parser, default="deflate", default_text="deflate")
    parser.add_argument("--comment", metavar="TEXT", help="archive comment")
    add_output_options(parser, verbose_help="list every member added", quiet=True)
    add_encryption_options(parser)
    add_password_options(parser)
