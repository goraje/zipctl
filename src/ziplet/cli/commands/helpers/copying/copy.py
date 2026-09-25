"""Reading the input archive and writing every member into the new one."""

from __future__ import annotations

import zlib
from collections.abc import Sequence

from ziplet.cli.archive import CHUNK
from ziplet.cli.atomic import replacing
from ziplet.cli.commands.helpers.copying.options import CopyJob
from ziplet.cli.commands.helpers.copying.report import report_copy
from ziplet.cli.commands.helpers.copying.targets import (
    Copied,
    Target,
    describe_failure,
)
from ziplet.cli.commands.helpers.copying.verify import verify_copy
from ziplet.cli.commands.helpers.passwords.pool import PasswordPool, PasswordProblem
from ziplet.cli.context import Context
from ziplet.cli.errors import EXIT_OK, CliError
from ziplet.cli.methods import (
    ENCRYPTION_METHODS,
    NO_ENCRYPTION,
    compression_label,
    method_of,
)
from ziplet.cli.output import printable
from ziplet.cryptography import wz_aes_stores_crc
from ziplet.zipfile.file import ZipFile
from ziplet.zipfile.info import ZipInfo


def read_passwords(
    zf: ZipFile, infos: Sequence[ZipInfo], pool: PasswordPool
) -> list[bytes | None]:
    """The password of every encrypted member (``None`` for plain ones).

    Stops at the first member that cannot be unlocked: the output would be
    incomplete, so there is no point asking for the rest.
    """
    passwords: list[bytes | None] = []
    for info in infos:
        if not info.is_encrypted:
            passwords.append(None)
            continue
        password = pool.resolve(zf, info)
        if isinstance(password, PasswordProblem):
            raise CliError(f"cannot read {printable(info.filename)}: {password.text}")
        passwords.append(password)
    return passwords


def _target_keeps_crc(target: Target) -> bool:
    """Whether a member written for *target* carries its CRC-32 (WZ-AES 2 does not)."""
    if not target.method.is_aes:
        return True
    return wz_aes_stores_crc(
        target.extra.force_wz_aes_version if target.extra else None
    )


def _can_copy_raw(info: ZipInfo, target: Target) -> bool:
    """Whether *info* can go to *target* without decompressing and compressing it.

    When the CRC-32 is lost on the way (from or to WZ-AES 2) the data is read once
    more to compute it, which a ZipCrypto member, being slow to decrypt, is not
    worth: that copy takes the ordinary path.
    """
    if info.stores_crc and _target_keeps_crc(target):
        return True
    return method_of(info) is not ENCRYPTION_METHODS["zipcrypto"]


def _checksum(src: ZipFile, info: ZipInfo, password: bytes | None) -> tuple[int, int]:
    """The CRC-32 and length of the data of *info*, read (and so checked) in full."""
    crc = size = 0
    with src.open(info, pwd=password) as reader:
        while chunk := reader.read(CHUNK):
            crc = zlib.crc32(chunk, crc)
            size += len(chunk)
    return crc, size


def _copy_compressed(
    src: ZipFile,
    dst: ZipFile,
    info: ZipInfo,
    new: ZipInfo,
    password: bytes | None,
    target: Target,
) -> tuple[int, int]:
    """Copy *info* with its compressed data as it is; returns its CRC-32 and size."""
    if info.stores_crc and _target_keeps_crc(target):
        crc, size = info.CRC, info.file_size  # not read: --verify checks them
    else:
        crc, size = _checksum(src, info, password)
    dst._copy_raw(  # noqa: SLF001 - the library hook made for this copy
        src,
        info,
        new,
        crc=crc,
        size=size,
        pwd=password,
        encryption=target.method.scheme,
        password=target.password,
        extra=target.extra,
    )
    return crc, size


def _recompress(
    src: ZipFile,
    dst: ZipFile,
    info: ZipInfo,
    new: ZipInfo,
    password: bytes | None,
    target: Target,
) -> tuple[int, int]:
    """Copy *info* by reading its data and compressing it again."""
    crc = size = 0
    with (
        src.open(info, pwd=password) as reader,
        dst.open(
            new,
            "w",
            encryption=target.method.scheme,
            password=target.password,
            extra=target.extra,
        ) as writer,
    ):
        while chunk := reader.read(CHUNK):
            crc = zlib.crc32(chunk, crc)
            size += len(chunk)
            writer.write(chunk)
    return crc, size


def _copy(
    src: ZipFile,
    dst: ZipFile,
    infos: Sequence[ZipInfo],
    passwords: Sequence[bytes | None],
    targets: Sequence[Target],
    compress_type: int | None,
    level: int | None,
) -> list[Copied]:
    copied = []
    for info, password, target in zip(infos, passwords, targets, strict=True):
        new = ZipInfo(info.filename, info.date_time)
        new.comment = info.comment
        new.external_attr = info.external_attr
        new.internal_attr = info.internal_attr
        new.create_system = info.create_system
        new.extra = info.carried_extra
        if info.is_dir():
            dst.mkdir(new)
            copied.append(
                Copied(info.filename, True, 0, 0, None, NO_ENCRYPTION, NO_ENCRYPTION)
            )
            continue
        new.compress_type = (
            info.compress_type if compress_type is None else compress_type
        )
        new.compress_level = level
        new.file_size = info.file_size
        raw = compress_type is None and _can_copy_raw(info, target)
        try:
            if raw:
                crc, size = _copy_compressed(src, dst, info, new, password, target)
            else:
                crc, size = _recompress(src, dst, info, new, password, target)
        except Exception as exc:
            raise CliError(
                f"cannot copy {printable(info.filename)}: {describe_failure(exc)}"
            ) from None
        copied.append(
            Copied(
                info.filename,
                False,
                size,
                crc,
                compression_label(new),
                method_of(info),
                target.method,
                raw,
            )
        )
    return copied


def run_copy(
    ctx: Context,
    src: ZipFile,
    passwords: Sequence[bytes | None],
    targets: Sequence[Target],
    job: CopyJob,
    *,
    verb: str,
    compress_type: int | None = None,
    level: int | None = None,
) -> int:
    """Copy every member of *src* per *targets* into ``job.output``, then report."""
    infos = src.infolist()
    with replacing(job.output, overwrite=job.force) as scratch:
        with ZipFile(scratch, "w", strict_timestamps=False) as dst:
            dst.comment = src.comment
            copied = _copy(src, dst, infos, passwords, targets, compress_type, level)
        if job.verify:
            verify_copy(scratch, src, infos, targets, copied)
    report_copy(ctx, job, verb, copied)
    return EXIT_OK
