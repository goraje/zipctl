"""Reading a new archive back to prove it holds what was meant to be written."""

from __future__ import annotations

import zlib
from collections.abc import Sequence

from zipctl.cli.archive import CHUNK
from zipctl.cli.commands.helpers.copy_targets import (
    Copied,
    Target,
    describe_failure,
)
from zipctl.cli.errors import EXIT_FAILURE, CliError
from zipctl.cli.methods import method_of
from zipctl.cli.output import printable
from zipctl.limits import ArchiveLimits
from zipctl.zipfile.file import ZipFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.shared import MASK_COMPRESS_OPTIONS

_SHOWN = 10  # problems listed before "and N more"


def verify_copy(
    path: str,
    src: ZipFile,
    infos: Sequence[ZipInfo],
    targets: Sequence[Target],
    copied: Sequence[Copied],
    limits: ArchiveLimits,
) -> None:
    """Read the new archive back; raise if it differs from what was intended."""
    try:
        out = ZipFile(path, limits=limits)
    except Exception as exc:
        raise CliError(
            f"the new archive cannot be read back: {describe_failure(exc)}"
        ) from None
    problems: list[str] = []
    with out:
        new_infos = out.infolist()
        same_count = len(new_infos) == len(infos)
        if not same_count:
            problems.append(f"expected {len(infos)} members but found {len(new_infos)}")
        if out.comment != src.comment:
            problems.append("the archive comment differs")
        if same_count:
            for old, new, target, record in zip(
                infos, new_infos, targets, copied, strict=True
            ):
                problems.extend(_member_problems(out, old, new, target, record))
    if problems:
        shown = problems[:_SHOWN]
        if len(problems) > _SHOWN:
            shown.append(f"and {len(problems) - _SHOWN} more")
        raise CliError(
            "verification of the new archive failed; nothing was written",
            EXIT_FAILURE,
            tuple(shown),
        )


def _member_problems(
    out: ZipFile, old: ZipInfo, new: ZipInfo, target: Target, record: Copied
) -> list[str]:
    name = printable(old.filename)
    if (
        new.filename,
        new.date_time,
        new.external_attr,
        new.internal_attr,
        new.create_system,
        new.comment,
        new.carried_extra,
    ) != (
        old.filename,
        old.date_time,
        old.external_attr,
        old.internal_attr,
        old.create_system,
        old.comment,
        old.carried_extra,
    ):
        return [f"{name}: name, date, mode, comment or extra fields differ"]
    if record.raw and (
        new.compress_type,
        new.flag_bits & MASK_COMPRESS_OPTIONS,
        new.file_size,
    ) != (old.compress_type, old.flag_bits & MASK_COMPRESS_OPTIONS, old.file_size):
        return [f"{name}: the compressed data was not copied as it was"]
    found = method_of(new)
    if found != target.method:
        return [f"{name}: is {found.label}, not {target.method.label}"]
    if old.is_dir():
        return []
    return _data_problems(out, new, target, record, name)


def _data_problems(
    out: ZipFile, new: ZipInfo, target: Target, record: Copied, name: str
) -> list[str]:
    crc = size = 0
    try:
        with out.open(new, pwd=target.password) as stream:
            while chunk := stream.read(CHUNK):
                crc = zlib.crc32(chunk, crc)
                size += len(chunk)
    except Exception as exc:
        return [f"{name}: {describe_failure(exc)}"]
    if size != record.size or crc != record.crc:
        return [f"{name}: the data read back differs from the data copied"]
    return []
