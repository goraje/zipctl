"""The ``list`` command."""

from __future__ import annotations

import stat
from dataclasses import dataclass
from typing import Protocol

from zipctl.cli.archive import open_archive
from zipctl.cli.commands.helpers.command import Subparsers, add_command
from zipctl.cli.commands.helpers.output_options import OutputArgs, add_output_options
from zipctl.cli.commands.helpers.selection import MEMBER_HELP, select_infos
from zipctl.cli.context import Context
from zipctl.cli.errors import EXIT_OK
from zipctl.cli.methods import compression_label, method_of
from zipctl.cli.output import (
    count,
    format_table,
    human_size,
    printable,
    write_json,
)
from zipctl.zipfile.file import ZipFile
from zipctl.zipfile.info import ZipInfo


class ListArgs(OutputArgs, Protocol):
    archive: str
    members: list[str]
    long: bool


def _timestamp(info: ZipInfo, separator: str) -> str:
    year, month, day, hour, minute, second = info.date_time
    date = f"{year:04d}-{month:02d}-{day:02d}"
    return f"{date}{separator}{hour:02d}:{minute:02d}:{second:02d}"


def _mode_text(info: ZipInfo) -> str:
    mode = info.unix_mode
    if not mode:
        return "-"
    if not stat.S_IFMT(mode):  # permissions only: the kind comes from the name
        mode |= stat.S_IFDIR if info.is_dir() else stat.S_IFREG
    return stat.filemode(mode)


def _saved(compressed: int, original: int) -> str:
    """The share of *original* that compression saved (``-`` for no data).

    Like ``unzip -v``: stored data saves ``0%``, data that grew is negative.
    """
    return f"{round(100 * (1 - compressed / original))}%" if original else "-"


@dataclass(frozen=True)
class Listed:
    """One member as ``list --json`` reports it."""

    name: str
    directory: bool
    is_symlink: bool
    size: int
    compressed_size: int
    modified: str
    compression: str
    encryption: str
    crc32: str
    mode: str | None
    comment: str


def _listed(info: ZipInfo) -> Listed:
    mode = info.unix_mode
    return Listed(
        info.filename,
        info.is_dir(),
        info.is_symlink(),
        info.file_size,
        info.compress_size,
        _timestamp(info, "T"),
        compression_label(info),
        method_of(info).label,
        f"{info.CRC:08x}",
        f"{mode:o}" if mode else None,
        info.comment.decode("utf-8", "replace"),
    )


def _list_json(ctx: Context, zf: ZipFile, archive: str, infos: list[ZipInfo]) -> None:
    write_json(
        ctx.stdout,
        {
            "ok": True,
            "archive": archive,
            "comment": zf.comment.decode("utf-8", "replace"),
            "member_count": len(infos),
            "members": [_listed(info) for info in infos],
        },
    )


def _crc_text(info: ZipInfo) -> str:
    """The CRC-32, or ``-`` where AE-2 does not store it."""
    return f"{info.CRC:08x}" if info.stores_crc else "-"


def _list_long(ctx: Context, zf: ZipFile, infos: list[ZipInfo]) -> None:
    encrypted = any(method_of(info).is_encrypted for info in infos)
    headers = ["Mode", "Length", "Compressed", "Saved", "Modified", "Method"]
    if encrypted:
        headers.append("Encryption")
    headers += ["CRC-32", "Name"]
    rows: list[list[str]] = []
    for info in infos:
        row = [
            _mode_text(info),
            str(info.file_size),
            str(info.compress_size),
            _saved(info.compress_size, info.file_size),
            _timestamp(info, " "),
            compression_label(info),
        ]
        if encrypted:
            row.append(method_of(info).label)
        rows.append([*row, _crc_text(info), printable(info.filename)])
    for line in format_table(headers, rows, right_aligned=(1, 2, 3)):
        ctx.out(line)
    total = sum(info.file_size for info in infos)
    stored = sum(info.compress_size for info in infos)
    footer = f"{count(len(infos), 'member')}, {human_size(total)}"
    if total:
        footer += f" ({human_size(stored)} compressed, {_saved(stored, total)} saved)"
    ctx.out("")
    ctx.out(footer)
    if zf.comment:
        ctx.out("")
        ctx.out("Comment:")
        for line in zf.comment.decode("utf-8", "replace").splitlines():
            ctx.out(f"  {printable(line)}")


def cmd_list(args: ListArgs, ctx: Context) -> int:
    with open_archive(args.archive) as zf:
        infos = select_infos(zf.infolist(), args.members)
        if args.json:
            _list_json(ctx, zf, args.archive, infos)
        elif args.long:
            _list_long(ctx, zf, infos)
        else:
            for info in infos:
                ctx.out(printable(info.filename))
    return EXIT_OK


def register(subparsers: Subparsers) -> None:
    parser = add_command(subparsers, "list", cmd_list, "list archive members")
    parser.add_argument("archive", metavar="ARCHIVE", help="the archive to list")
    parser.add_argument("members", nargs="*", metavar="MEMBER", help=MEMBER_HELP)
    parser.add_argument(
        "-l",
        "--long",
        action="store_true",
        help="show modes, sizes, space saved, dates, methods and the archive comment",
    )
    add_output_options(parser)
