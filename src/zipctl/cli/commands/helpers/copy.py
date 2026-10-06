"""Copying an archive member by member: options, targets, verification and report."""

from __future__ import annotations

import argparse
import os
from collections.abc import Callable, Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from zipctl.cli.archive import open_archive
from zipctl.cli.atomic import replacing
from zipctl.cli.commands.helpers.encryption_plan import UNPROTECTED, Protection
from zipctl.cli.commands.helpers.output_options import add_output_options
from zipctl.cli.commands.helpers.passwords import PasswordPool, PasswordProblem
from zipctl.cli.context import Context
from zipctl.cli.errors import EXIT_FAILURE, EXIT_OK, CliError, UsageError
from zipctl.cli.methods import (
    NO_ENCRYPTION,
    EncryptionMethod,
    compression_label,
    method_of,
)
from zipctl.cli.output import Output, count, printable
from zipctl.cli.reports import CopyMember, CopyReport
from zipctl.limits import ArchiveLimits
from zipctl.zipfile.file import (
    INHERIT_ENCRYPTION,
    CopiedMember,
    ZipFile,
    ZipFileExtra,
)
from zipctl.zipfile.file.copy_check import copy_problem
from zipctl.zipfile.info import ZipInfo

# --- copy intents and protection ------------------------------------------


class Intent(Enum):
    """What one member becomes in a member copy (a directory is always plain)."""

    PLAIN = "plain"  # written unencrypted
    KEEP = "keep"  # copied as stored, its protection untouched; needs no password
    SAME = "same"  # read, then written again with the protection it has
    NEW = "new"  # written with the protection :meth:`MemberCopy.run` is given


def _same(info: ZipInfo, password: bytes | None) -> Protection:
    """The protection *info* already has, to write it again with *password*."""
    method = method_of(info)
    if not method.is_encrypted:
        return UNPROTECTED
    if info.aes_extra is None:
        return Protection(method, password)
    extra = ZipFileExtra(
        force_wz_aes_version=info.aes_extra.wz_aes_version, wz_aes_nbits=method.aes_bits
    )
    return Protection(method, password, extra)


@dataclass
class Copied:
    """What was written for one member."""

    name: str
    directory: bool
    compression: str | None
    before: EncryptionMethod
    after: EncryptionMethod
    result: CopiedMember


def describe_failure(exc: Exception) -> str:
    return printable(str(exc) or type(exc).__name__)


# --- copy options ----------------------------------------------------------


class CopyArgs(Protocol):
    """What :func:`add_copy_options` leaves on the parsed arguments."""

    input: str
    output: str
    force: bool
    no_verify: bool


@dataclass(frozen=True)
class CopyJob:
    """What :func:`add_copy_options` collects: the files and whether to verify."""

    input: str
    output: str
    force: bool
    verify: bool


def _job(args: CopyArgs) -> CopyJob:
    return CopyJob(
        args.input,
        args.output,
        args.force,
        not args.no_verify,
    )


def _check_paths(job: CopyJob) -> None:
    """Refuse an output that is the input, or that exists without ``--force``."""
    try:
        same = os.path.samefile(job.input, job.output)
    except OSError:
        same = False
    if same:
        raise UsageError(
            f"{printable(job.output)} is the input archive; zipctl never rewrites "
            "an archive in place (write a new file, then move it over the original)",
        )
    if os.path.lexists(job.output) and not job.force:
        raise CliError(
            f"{printable(job.output)} already exists (use --force to replace it)"
        )


def add_copy_options(parser: argparse.ArgumentParser) -> None:
    """The arguments every copying command takes."""
    parser.add_argument("input", metavar="INPUT", help="the archive to read")
    parser.add_argument(
        "output", metavar="OUTPUT", help="the new archive (never the input itself)"
    )
    parser.add_argument(
        "--force", action="store_true", help="replace OUTPUT if it exists"
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip reading OUTPUT back before moving it into place",
    )
    add_output_options(parser, verbose_help="list every member", quiet=True)


# --- copy verify -----------------------------------------------------------

_SHOWN = 10  # problems listed before "and N more"


def verify_copy(
    path: str,
    src: ZipFile,
    infos: Sequence[ZipInfo],
    protections: Sequence[Protection],
    kept: Sequence[bool],
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
            for old, new, protection, keep, record in zip(
                infos, new_infos, protections, kept, copied, strict=True
            ):
                problem = _member_problem(src, out, old, new, protection, keep, record)
                if problem is not None:
                    problems.append(f"{printable(old.filename)}: {printable(problem)}")
    if problems:
        shown = problems[:_SHOWN]
        if len(problems) > _SHOWN:
            shown.append(f"and {len(problems) - _SHOWN} more")
        raise CliError(
            "verification of the new archive failed; nothing was written",
            EXIT_FAILURE,
            tuple(shown),
        )


def _member_problem(
    src: ZipFile,
    out: ZipFile,
    old: ZipInfo,
    new: ZipInfo,
    protection: Protection,
    keep: bool,
    record: Copied,
) -> str | None:
    found = method_of(new)
    if found != protection.method:
        return f"is {found.label}, not {protection.method.label}"
    return copy_problem(
        src, old, out, new, record.result, pwd=protection.password, kept=keep
    )


# --- copy report -----------------------------------------------------------


def report_copy(output: Output, job: CopyJob, verb: str, copied: list[Copied]) -> None:
    files = [c for c in copied if not c.directory]
    encrypted = sum(c.after.is_encrypted for c in files)
    if output.json:
        members: list[CopyMember] = [
            {
                "name": c.name,
                "directory": c.directory,
                "size": c.result.size,
                "compression": c.compression,
                "encryption_before": c.before.label,
                "encryption_after": c.after.label,
            }
            for c in copied
        ]
        report: CopyReport = {
            "ok": True,
            "input": job.input,
            "output": job.output,
            "verified": job.verify,
            "file_count": len(files),
            "directory_count": len(copied) - len(files),
            "encrypted_count": encrypted,
            "members": members,
        }
        output.document(report)
        return
    for c in copied:
        if c.directory:
            output.detail(f"Copying: {printable(c.name)} (directory)")
            continue
        change = c.after.label
        if c.before != c.after:
            change = f"{c.before.label} -> {change}"
        output.detail(f"Copying: {printable(c.name)} ({c.compression}, {change})")
    parts = [
        count(len(files), "file"),
        count(len(copied) - len(files), "directory", "directories"),
    ]
    if encrypted:
        parts.append(f"{encrypted} encrypted")
    verified = " (verified)" if job.verify else ""
    output.summary(
        f"{verb} {printable(job.input)} into {printable(job.output)}: "
        f"{', '.join(parts)}{verified}"
    )


# --- copy ------------------------------------------------------------------


def _unlock(
    zf: ZipFile, infos: Sequence[ZipInfo], kept: Sequence[bool], pool: PasswordPool
) -> list[bytes | None]:
    """The password of every member that has to be decrypted (else ``None``).

    A member kept as stored needs none.  Stops at the first member that
    cannot be unlocked: the output would be incomplete, so there is no point
    asking for the rest.
    """
    passwords: list[bytes | None] = []
    for info, keep in zip(infos, kept, strict=True):
        if not info.is_encrypted or keep:
            passwords.append(None)
            continue
        try:
            password = pool.resolve(zf, info)
        except Exception as exc:
            name = printable(info.filename)
            raise CliError(f"cannot copy {name}: {describe_failure(exc)}") from None
        if isinstance(password, PasswordProblem):
            reason = pool.explain(password)
            raise CliError(f"cannot read {printable(info.filename)}: {reason}")
        passwords.append(password)
    return passwords


def _copy(
    src: ZipFile,
    dst: ZipFile,
    infos: Sequence[ZipInfo],
    passwords: Sequence[bytes | None],
    protections: Sequence[Protection],
    kept: Sequence[bool],
    compress_type: int | None,
    level: int | None,
) -> list[Copied]:
    copied: list[Copied] = []
    for info, password, protection, keep in zip(
        infos, passwords, protections, kept, strict=True
    ):
        try:
            result = dst.copy_member(
                src,
                info,
                pwd=password,
                compress_type=compress_type,
                compresslevel=level,
                encryption=INHERIT_ENCRYPTION if keep else protection.method.scheme,
                password=protection.password,
                extra=protection.extra,
                keep_encryption=keep,
            )
        except Exception as exc:
            raise CliError(
                f"cannot copy {printable(info.filename)}: {describe_failure(exc)}"
            ) from None
        directory = info.is_dir()
        copied.append(
            Copied(
                info.filename,
                directory,
                None if directory else compression_label(result.info),
                NO_ENCRYPTION if directory else method_of(info),
                NO_ENCRYPTION if directory else protection.method,
                result,
            )
        )
    return copied


class MemberCopy:
    """An input archive open to be copied, member by member, into a new one."""

    def __init__(self, ctx: Context, src: ZipFile, job: CopyJob) -> None:
        self._ctx: Context = ctx
        self._src: ZipFile = src
        self._job: CopyJob = job
        self.infos: list[ZipInfo] = src.infolist()

    def run(
        self,
        intent: Callable[[ZipInfo], Intent],
        *,
        verb: str,
        pool: PasswordPool | None = None,
        protect: Callable[[ZipInfo], Protection] | None = None,
        compress_type: int | None = None,
        level: int | None = None,
    ) -> int:
        """Write every member as *intent* says, verify the result, then report.

        Every member that is read is unlocked with *pool* first; only then is
        *protect* asked for the protection of each ``Intent.NEW`` member, so
        new passwords are asked for after the old ones.
        """
        ctx, src, job, infos = self._ctx, self._src, self._job, self.infos
        intents = [Intent.PLAIN if info.is_dir() else intent(info) for info in infos]
        kept = [
            i is Intent.KEEP and info.is_encrypted
            for info, i in zip(infos, intents, strict=True)
        ]
        pool = pool or PasswordPool([], ctx, can_prompt=False)
        passwords = _unlock(src, infos, kept, pool)
        protections: list[Protection] = []
        for info, i, keep, password in zip(
            infos, intents, kept, passwords, strict=True
        ):
            if i is Intent.NEW:
                assert protect is not None, "Intent.NEW needs a protect function"
                protections.append(protect(info))
            elif i is Intent.SAME:
                protections.append(_same(info, password))
            elif keep:
                protections.append(Protection(method_of(info)))
            else:
                protections.append(UNPROTECTED)
        with replacing(job.output, overwrite=job.force, mode_from=job.input) as scratch:
            with ZipFile(scratch, "w", strict_timestamps=False) as dst:
                dst.comment = src.comment
                copied = _copy(
                    src, dst, infos, passwords, protections, kept, compress_type, level
                )
            if job.verify:
                verify_copy(scratch, src, infos, protections, kept, copied, ctx.limits)
        report_copy(ctx.output, job, verb, copied)
        return EXIT_OK


@contextmanager
def open_copy(args: CopyArgs, ctx: Context) -> Generator[MemberCopy]:
    """Check where the copy goes, then open its input archive."""
    job = _job(args)
    _check_paths(job)
    with open_archive(job.input, ctx) as src:
        yield MemberCopy(ctx, src, job)
