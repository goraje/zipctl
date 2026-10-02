"""Extracting members of a ZipFile."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import IO, Protocol, TypeAlias

from zipctl.zipfile.extract import (
    ExtractPolicy,
    ExtractResult,
    MemberStatus,
    OverwritePolicy,
    normalized_destination,
)
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.materialize import (
    ExtractionQuota,
    MaterializationResult,
    materialize_member,
)
from zipctl.zipfile.policy_extraction import extract_with_policy
from zipctl.zipfile.progress import (
    ProgressCallback,
    ProgressReporter,
    propagate_callback_errors,
)
from zipctl.zipfile.shared import ReadWriteMode, StrPath
from zipctl.zipfile.validators import member_target_name

__all__ = ["PasswordProvider"]


class _Archive(Protocol):
    """The part of ``ZipFile`` extraction uses."""

    def getinfo(self, name: str) -> ZipInfo: ...

    def open(
        self, name: str | ZipInfo, mode: ReadWriteMode = "r", pwd: bytes | None = None
    ) -> IO[bytes]: ...


# Extraction can take one password for the whole archive, or a callable that is
# asked for the password of each encrypted member (return None for "unknown").
PasswordProvider: TypeAlias = Callable[[ZipInfo], bytes | None]


def password_for(member: ZipInfo, pwd: bytes | PasswordProvider | None) -> bytes | None:
    """Resolve *pwd* for *member*; a provider is asked only for encrypted members."""
    if pwd is None or isinstance(pwd, bytes):
        return pwd
    return pwd(member) if member.is_encrypted else None


def extract_all_with_progress(
    zf: _Archive,
    members: list[str | ZipInfo],
    path: str,
    pwd: bytes | PasswordProvider | None,
    progress: ProgressCallback,
) -> list[Path]:
    infos = [m if isinstance(m, ZipInfo) else zf.getinfo(m) for m in members]
    reporter = ProgressReporter(
        progress, len(infos), sum(info.file_size for info in infos)
    )
    targets: list[Path] = []
    with propagate_callback_errors():
        for index, info in enumerate(infos):
            reporter.start(index, info)
            result = extract_member(zf, info, path, pwd, reporter=reporter)
            reporter.finish(MemberStatus.EXTRACTED, result.bytes_written)
            targets.append(result.target)
    return targets


def extract_members_with_policy(
    zf: _Archive,
    members: list[str | ZipInfo],
    path: StrPath | None,
    pwd: bytes | PasswordProvider | None,
    policy: ExtractPolicy,
    progress: ProgressCallback | None = None,
) -> ExtractResult:
    destination = normalized_destination(path or os.getcwd())
    policy_root = (
        normalized_destination(policy.destination_root)
        if policy.destination_root is not None
        else destination
    )
    infos = [
        member if isinstance(member, ZipInfo) else zf.getinfo(member)
        for member in members
    ]
    reporter = (
        None
        if progress is None
        else ProgressReporter(
            progress, len(infos), sum(info.file_size for info in infos)
        )
    )
    with propagate_callback_errors():
        return extract_with_policy(
            infos,
            destination,
            policy_root,
            policy,
            lambda info, target, quota, reporter: extract_member(
                zf,
                info,
                str(destination),
                pwd,
                target_override=target,
                quota=quota,
                fsync=policy.fsync_files,
                overwrite=(
                    OverwritePolicy.REPLACE
                    if policy.allow_overwrite
                    else policy.overwrite_policy
                ),
                reporter=reporter,
                plain=False,
            ),
            reporter,
        )


def extract_member(
    zf: _Archive,
    member: str | ZipInfo,
    destination: str,
    pwd: bytes | PasswordProvider | None,
    *,
    target_override: Path | None = None,
    quota: ExtractionQuota | None = None,
    fsync: bool = True,
    reporter: ProgressReporter | None = None,
    overwrite: OverwritePolicy = OverwritePolicy.REPLACE,
    plain: bool = True,
) -> MaterializationResult:
    """Extract *member* to *targetpath* and return the materialization result.

    Resolves the platform path, guards against path traversal, creates
    parent directories as needed, and writes the file content (or creates
    a directory) at the resolved location.

    Args:
        member: Archive member name or
            :class:`~zipctl.zipfile.info.ZipInfo` instance.
        destination: Root directory under which the member is extracted.
        pwd: Decryption password, or ``None``.
        plain: Write symlink and special-file members as regular files, as
            the standard library does; policy extraction passes ``False`` and
            decides about them with ``allow_symlinks``/``allow_special_files``.

    Returns:
        The :class:`~zipctl.zipfile.materialize.MaterializationResult`
        describing what was written.

    Raises:
        ValueError: If the sanitized archive name is empty for a file
            entry.
    """
    if not isinstance(member, ZipInfo):
        member = zf.getinfo(member)

    _, parts = member_target_name(member.filename)
    arcname = os.path.sep.join(parts)

    if not arcname and not member.is_dir():
        raise ValueError("Empty filename.")

    if target_override is None:
        targetpath = os.path.normpath(os.path.join(destination, arcname))
    else:
        targetpath = os.fspath(target_override)

    return materialize_member(
        member,
        targetpath,
        lambda: zf.open(member, pwd=password_for(member, pwd)),
        destination,
        quota,
        fsync=fsync,
        reporter=reporter,
        overwrite=overwrite,
        plain=plain,
    )
