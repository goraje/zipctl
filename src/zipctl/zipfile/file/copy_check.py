"""Checking a member copy against what :meth:`ZipFile.copy_member` promises.

Not exported: the promise is the library's, so its check lives beside it;
callers that read a new archive back ask here whether each member held.
"""

from __future__ import annotations

from contextlib import closing
from itertools import zip_longest

from zipctl.zipfile.file import CopiedMember, ZipFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.shared import MASK_COMPRESS_OPTIONS, MASK_UTF_FILENAME, checksum

__all__ = ["copy_problem"]


def _failure(exc: Exception) -> str:
    return str(exc) or type(exc).__name__


def copy_problem(
    source: ZipFile,
    member: ZipInfo,
    copy: ZipFile,
    new: ZipInfo,
    copied: CopiedMember,
    *,
    pwd: bytes | None = None,
    kept: bool = False,
) -> str | None:
    """Why *new* in *copy* is not a faithful copy of *member* of *source*.

    *copied* is what :meth:`ZipFile.copy_member` returned for it, *pwd* the
    password the copy is read back with, and *kept* says it was copied with
    ``keep_encryption``: its stored bytes are compared, as nothing can be
    decrypted.  Returns ``None`` for a faithful copy.
    """
    if (
        new.filename,
        new.date_time,
        new.external_attr,
        new.internal_attr,
        new.create_system,
        new.comment,
        new.carried_extra,
    ) != (
        member.filename,
        member.date_time,
        member.external_attr,
        member.internal_attr,
        member.create_system,
        member.comment,
        member.carried_extra,
    ):
        return "name, date, mode, comment or extra fields differ"
    if copied.raw and (
        new.compress_type,
        new.flag_bits & MASK_COMPRESS_OPTIONS,
        new.file_size,
    ) != (
        member.compress_type,
        member.flag_bits & MASK_COMPRESS_OPTIONS,
        member.file_size,
    ):
        return "the compressed data was not copied as it was"
    if member.is_dir():
        return None
    if kept:
        return _stored_problem(source, member, copy, new)
    return _data_problem(copy, new, copied, pwd)


def _stored_problem(
    source: ZipFile, member: ZipInfo, copy: ZipFile, new: ZipInfo
) -> str | None:
    bits = ~MASK_UTF_FILENAME  # the writer may mark a re-encoded name UTF-8
    # an AE-2 member's CRC is written as 0, whatever the source stored
    crc = member.CRC if member.stores_crc else 0
    if (new.CRC, new.compress_size, new.file_size, new.flag_bits & bits) != (
        crc,
        member.compress_size,
        member.file_size,
        member.flag_bits & bits,
    ):
        return "the stored data was not copied as it was"
    try:
        with (
            closing(source.stored_chunks(member)) as a_chunks,
            closing(copy.stored_chunks(new)) as b_chunks,
        ):
            same = all(a == b for a, b in zip_longest(a_chunks, b_chunks))
    except Exception as exc:
        return _failure(exc)
    return None if same else "the stored data was not copied as it was"


def _data_problem(
    copy: ZipFile, new: ZipInfo, copied: CopiedMember, pwd: bytes | None
) -> str | None:
    try:
        with copy.open(new, pwd=pwd) as stream:
            crc, size = checksum(stream)
    except Exception as exc:
        return _failure(exc)
    if size != copied.size or crc != copied.crc:
        return "the data read back differs from the data copied"
    return None
