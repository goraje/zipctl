"""Composable metadata validators for policy-enabled extraction."""

from __future__ import annotations

import ntpath
import os
import posixpath
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from zipctl.exceptions import BadZipFile
from zipctl.zipfile.assessment import ExtractionContext, ValidationState, target_key
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.policy import (
    ExtractPolicy,
    ExtractViolation,
    OverwritePolicy,
    ViolationAction,
    compression_ratio,
    resolve_rule,
)
from zipctl.zipfile.records import raise_for_unsupported_flags

_WINDOWS_ILLEGAL_NAME_CHARS = ':<>|"?*' + "".join(chr(i) for i in range(32))
_WINDOWS_ILLEGAL_NAME_TABLE = str.maketrans(
    _WINDOWS_ILLEGAL_NAME_CHARS, "_" * len(_WINDOWS_ILLEGAL_NAME_CHARS)
)

_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"{port}{n}" for port in ("COM", "LPT") for n in "123456789\xb9\xb2\xb3"}
)


@dataclass(frozen=True)
class ValidatorParams:
    """Bundles one member validator call's arguments.

    A validator only reads the fields it needs — no unused-parameter
    ceremony for the checks that ignore ``target`` or ``state``.
    """

    info: ZipInfo
    target: Path
    context: ExtractionContext
    state: ValidationState


class MemberValidator(Protocol):
    """Protocol implemented by one metadata-only member validator."""

    def __call__(self, params: ValidatorParams) -> Iterable[ExtractViolation]: ...


def _violation(
    info: ZipInfo,
    code: str,
    message: str,
    target: Path | None = None,
    action: ViolationAction = ViolationAction.ERROR,
) -> ExtractViolation:
    return ExtractViolation(info.filename, code, message, action, target)


def entry_mode(info: ZipInfo) -> int:
    return info.unix_mode & 0o170000


def entry_type(info: ZipInfo) -> tuple[bool, bool]:
    mode = entry_mode(info)
    is_symlink = stat.S_ISLNK(mode)
    is_special = bool(
        mode and not is_symlink and not stat.S_ISREG(mode) and not stat.S_ISDIR(mode)
    )
    return is_symlink, is_special


def has_parent_component(raw_name: str) -> bool:
    """Return whether *raw_name* contains a ``..`` path component.

    Both ``/`` and ``\\`` count as separators, since archives written on
    Windows may use either.
    """
    return ".." in raw_name.replace("\\", "/").split("/")


def _windows_reserved(part: str) -> bool:
    """Whether *part* names a device (``CON``, ``nul.txt``, ``COM1``) on Windows."""
    return part.split(".", 1)[0].rstrip(" ").upper() in _WINDOWS_RESERVED_NAMES


def _sanitize_windows_name(arcname: str, pathsep: str) -> str:
    """Sanitize *arcname* for extraction on a Windows filesystem.

    Replaces characters illegal in Windows filenames with underscores, strips
    trailing spaces and dots from each path component, and prefixes device
    names with an underscore so they are written as ordinary files.
    """
    arcname = arcname.translate(_WINDOWS_ILLEGAL_NAME_TABLE)
    parts = (x.rstrip(" .") for x in arcname.split(pathsep))
    return pathsep.join(f"_{x}" if _windows_reserved(x) else x for x in parts if x)


def member_target_name(raw_name: str) -> tuple[str, list[str]]:
    target_name = raw_name.replace("/", os.path.sep)
    drive, _ = ntpath.splitdrive(raw_name)
    if os.path.sep == "\\":
        target_name = _sanitize_windows_name(target_name, os.path.sep)
    parts = [
        part
        for part in target_name.split(os.path.sep)
        if part not in ("", os.path.curdir, os.path.pardir)
    ]
    return drive, parts


def resolve_extract_target(
    info: ZipInfo, destination: Path
) -> tuple[Path, str, list[str]]:
    """Resolve the filesystem target for *info*. Pure — produces no violations."""
    drive, parts = member_target_name(info.filename)
    target = destination / os.path.sep.join(parts)
    return target, drive, parts


def check_absolute_path(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, context = params.info, params.context
    rule = resolve_rule(
        context.policy.allow_absolute_paths, context.policy.on_violation
    )
    if (
        posixpath.isabs(info.filename) or ntpath.isabs(info.filename)
    ) and not rule.value:
        yield _violation(
            info, "absolute_path", "absolute path is not allowed", action=rule.action
        )


def check_windows_drive_and_unc(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, context = params.info, params.context
    raw = info.filename
    drive, _ = ntpath.splitdrive(raw)
    rule = resolve_rule(
        context.policy.allow_windows_drive_paths, context.policy.on_violation
    )
    if rule.value:
        return
    if raw.startswith(("\\\\", "//")):
        yield _violation(
            info, "windows_path", "Windows UNC path is not allowed", action=rule.action
        )
    elif drive:
        yield _violation(
            info,
            "windows_drive_path",
            "Windows drive path is not allowed",
            action=rule.action,
        )


def check_parent_traversal(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, context = params.info, params.context
    raw = info.filename
    rule = resolve_rule(
        context.policy.allow_parent_traversal, context.policy.on_violation
    )
    if has_parent_component(raw) and not rule.value:
        yield _violation(
            info,
            "parent_traversal",
            "parent traversal is not allowed",
            action=rule.action,
        )


def check_outside_root(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    try:
        target.resolve().relative_to(context.policy_root)
    except ValueError:
        yield _violation(
            info,
            "outside_root",
            "target escapes destination root",
            target,
            context.policy.on_violation,
        )


def check_path_limits(params: ValidatorParams) -> Iterable[ExtractViolation]:
    """Refuse targets too long or too deep for the filesystem to take safely.

    Unlike other limits these default to ERROR whatever ``on_violation`` says:
    writing such a path would fail part way through the extraction.
    """
    info, target, context = params.info, params.target, params.context
    policy = context.policy
    length = resolve_rule(policy.max_path_length, ViolationAction.ERROR)
    if length.value is not None and len(os.fsencode(target)) > length.value:
        yield _violation(
            info, "max_path_length", "target path is too long", target, length.action
        )
    depth = resolve_rule(policy.max_path_depth, ViolationAction.ERROR)
    parts = target.relative_to(context.destination).parts
    if depth.value is not None and len(parts) > depth.value:
        yield _violation(
            info, "max_path_depth", "target path is too deep", target, depth.action
        )


def check_duplicate_target(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context, state = (
        params.info,
        params.target,
        params.context,
        params.state,
    )
    rule = resolve_rule(
        context.policy.reject_duplicate_targets, context.policy.on_violation
    )
    key = target_key(target)
    if key in state.targets:
        state.duplicate_targets.append(target)
    if key in state.targets and rule.value:
        yield _violation(
            info,
            "duplicate_target",
            f"target duplicates {state.targets[key]!r}",
            target,
            rule.action,
        )
    else:
        state.targets[key] = info.filename


def _file_type(path: Path) -> int:
    """The type bits of *path* itself (a symlink is not followed), 0 if missing."""
    try:
        return stat.S_IFMT(os.lstat(path).st_mode)
    except (OSError, ValueError):  # Windows: ValueError for a path too long
        return 0


def check_overwrite_conflict(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, policy = params.info, params.target, params.context.policy
    kind = _file_type(target)
    # A directory member onto an existing directory (not a link) merges.
    if not kind or (info.is_dir() and kind == stat.S_IFDIR):
        return
    overwrite = policy.overwrite_policy
    if overwrite not in (OverwritePolicy.REPLACE, OverwritePolicy.RENAME):
        action = (
            ViolationAction.ERROR
            if overwrite == OverwritePolicy.ERROR
            else ViolationAction.SKIP
        )
        yield ExtractViolation(
            info.filename, "overwrite", "target already exists", action, target
        )
    # Writing would fail after earlier members were written: a directory member
    # never replaces anything nor is renamed, and REPLACE keeps a directory.
    elif info.is_dir():
        yield _violation(info, "overwrite", "target is not a directory", target)
    elif (
        kind == stat.S_IFDIR
        and overwrite == OverwritePolicy.REPLACE
        and _creates_non_directory(info, policy)
    ):
        yield _violation(info, "overwrite", "target is a directory", target)


def check_max_member_size(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.max_member_size, context.policy.on_violation)
    if rule.value is not None and info.file_size > rule.value:
        yield _violation(
            info, "max_member_size", "member exceeds size limit", target, rule.action
        )


def check_compression_ratio(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(
        context.policy.max_compression_ratio, context.policy.on_violation
    )
    ratio = compression_ratio(info)
    if rule.value is not None and ratio is not None and ratio > rule.value:
        yield _violation(
            info,
            "compression_ratio",
            "compression ratio exceeds limit",
            target,
            rule.action,
        )


def name_suffixes(filename: str) -> list[str]:
    """Return the dotted suffixes of *filename*: ``a.tar.gz`` gives ``[".tar", ".gz"]``.

    Dot handling follows :class:`pathlib.Path`: leading dots do not start a
    suffix.
    """
    path = Path(filename)
    # Before Python 3.14 a trailing dot means "no suffix"; keep that everywhere
    # so a name matches the same rules on every supported version.
    return [] if path.name.endswith(".") else path.suffixes


def extension_chains(filename: str) -> frozenset[str]:
    """Return every trailing chain of dotted suffixes of *filename*, lower-cased.

    ``a.tar.gz`` gives ``{".gz", ".tar.gz"}``.  A name without a suffix
    (``README``, ``.bashrc``) gives ``{""}``, so ``""`` stands for "no
    extension".  A rule entry matches when it is one of these chains.
    """
    suffixes = [s.lower() for s in name_suffixes(filename)]
    if not suffixes:
        return frozenset({""})
    return frozenset("".join(suffixes[start:]) for start in range(len(suffixes)))


def check_extension_allowed(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.allowed_extensions, context.policy.on_violation)
    if (
        not info.is_dir()
        and rule.value is not None
        and extension_chains(target.name).isdisjoint(rule.value)
    ):
        yield _violation(
            info,
            "extension_not_allowed",
            "extension is not allowed",
            target,
            rule.action,
        )


def check_extension_blocked(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.blocked_extensions, context.policy.on_violation)
    if (
        not info.is_dir()
        and rule.value is not None
        and not extension_chains(target.name).isdisjoint(rule.value)
    ):
        yield _violation(
            info, "extension_blocked", "extension is blocked", target, rule.action
        )


def check_symlink_allowed(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.allow_symlinks, context.policy.on_violation)
    mode = entry_mode(info)
    if stat.S_ISLNK(mode) and not rule.value:
        yield _violation(
            info, "symlink", "symlink extraction is not allowed", target, rule.action
        )


def _creates_non_directory(info: ZipInfo, policy: ExtractPolicy) -> bool:
    if info.is_dir():
        return False
    is_symlink, is_special = entry_type(info)
    if not (is_symlink or is_special):
        return True
    # A refused one is never created: these refusals are never only a warning.
    field = policy.allow_symlinks if is_symlink else policy.allow_special_files
    return bool(resolve_rule(field, policy.on_violation).value)


def _parent_violation(parent: Path, state: ValidationState) -> tuple[str, str] | None:
    """Why no member can be written below *parent*, if it cannot."""
    key = target_key(parent)
    path = os.fspath(parent)
    if path not in state.file_types:  # one lstat per parent, not per member
        state.file_types[path] = _file_type(parent)
    kind = state.file_types[path]
    # An archived non-directory never displaces a real directory: writing
    # refuses, skips or renames it.
    if kind != stat.S_IFDIR and key in state.symlinks:
        kind = stat.S_IFLNK
    elif kind != stat.S_IFDIR and key in state.files:
        kind = stat.S_IFREG
    if kind == stat.S_IFLNK:
        return "symlink_parent", f"path runs through the symbolic link {path!r}"
    if kind not in (0, stat.S_IFDIR):
        return "parent_conflict", f"path runs through the file {path!r}"
    return None


def check_parents(params: ValidatorParams) -> Iterable[ExtractViolation]:
    """Refuse a member whose path runs through a symlink or a file, archived or
    on disk, and a non-directory where an earlier member needs a directory.

    Writing would refuse it anyway, but only after earlier members were
    written; finding it here keeps the archive's "nothing written" promise.
    The second clash is an overwrite: SKIP and RENAME resolve it.
    """
    info, target, context, state = (
        params.info,
        params.target,
        params.context,
        params.state,
    )
    try:
        parts = target.relative_to(context.destination).parts
    except ValueError:  # reported by check_outside_root
        return
    parents = [context.destination.joinpath(*parts[:n]) for n in range(1, len(parts))]
    for parent in parents:
        found = _parent_violation(parent, state)
        if found is not None:
            yield _violation(info, *found, target)
            break
    for parent in parents:
        state.parents.setdefault(target_key(parent), info.filename)
    policy = context.policy
    if not _creates_non_directory(info, policy):
        return
    key = target_key(target)
    if key in state.parents:
        overwrite = policy.overwrite_policy
        if overwrite != OverwritePolicy.RENAME:  # else written beside it
            yield _violation(
                info,
                "parent_conflict",
                f"target is a directory {state.parents[key]!r} needs",
                target,
                ViolationAction.SKIP
                if overwrite == OverwritePolicy.SKIP
                else ViolationAction.ERROR,
            )
    elif stat.S_ISLNK(entry_mode(info)):
        state.symlinks.add(key)
    else:
        state.files.add(key)


def check_special_file_allowed(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.allow_special_files, context.policy.on_violation)
    mode = entry_mode(info)
    if (
        mode
        and not stat.S_ISREG(mode)
        and not stat.S_ISDIR(mode)
        and not stat.S_ISLNK(mode)
        and not rule.value
    ):
        yield _violation(
            info,
            "special_file",
            "special file extraction is not allowed",
            target,
            rule.action,
        )


def check_utf8_name(params: ValidatorParams) -> Iterable[ExtractViolation]:
    info, target, context = params.info, params.target, params.context
    rule = resolve_rule(context.policy.require_utf8_names, context.policy.on_violation)
    if (
        rule.value
        and not info.is_utf_filename
        and any(ord(char) > 127 for char in info.orig_filename)
    ):
        yield _violation(
            info, "non_utf8_name", "member name is not UTF-8", target, rule.action
        )


def check_custom_validator(params: ValidatorParams) -> Iterable[ExtractViolation]:
    """Run each user-supplied validator; every rejection is its own violation."""
    info, target, policy = params.info, params.target, params.context.policy
    configured = policy.custom_validator
    if configured is None:
        return
    validators = (configured,) if callable(configured) else tuple(configured)
    for validator in validators:
        try:
            validator(info, target)
        except (OSError, ValueError, BadZipFile, RuntimeError) as exc:
            yield _violation(
                info, "custom_validator", str(exc), target, policy.on_violation
            )


def check_total_uncompressed_size(
    params: ValidatorParams,
) -> Iterable[ExtractViolation]:
    info, target, context, state = (
        params.info,
        params.target,
        params.context,
        params.state,
    )
    rule = resolve_rule(
        context.policy.max_total_uncompressed_size, context.policy.on_violation
    )
    if rule.value is not None and state.total_declared > rule.value:
        yield _violation(
            info,
            "max_total_uncompressed_size",
            "total declared uncompressed size exceeds policy limit",
            target,
            rule.action,
        )


def check_supported(params: ValidatorParams) -> Iterable[ExtractViolation]:
    """Refuse a member whose method or flags this archive cannot read."""
    info = params.info
    try:
        params.context.registry.check_compression(info.compress_type)
        raise_for_unsupported_flags(info)
    except (NotImplementedError, RuntimeError) as exc:
        yield _violation(info, "unsupported", f"cannot be extracted: {exc}")


EXTRACT_VALIDATORS: tuple[MemberValidator, ...] = (
    check_supported,
    check_absolute_path,
    check_windows_drive_and_unc,
    check_parent_traversal,
    check_outside_root,
    check_path_limits,
    check_duplicate_target,
    check_overwrite_conflict,
    check_max_member_size,
    check_compression_ratio,
    check_extension_allowed,
    check_extension_blocked,
    check_symlink_allowed,
    check_parents,
    check_special_file_allowed,
    check_utf8_name,
    check_custom_validator,
    check_total_uncompressed_size,
)

# The rules a RENAME candidate is checked against again: a renamed target
# keeps its parent, so only the rules that read the target's name can differ.
TARGET_NAME_VALIDATORS: tuple[MemberValidator, ...] = (
    check_path_limits,
    check_extension_allowed,
    check_extension_blocked,
    check_custom_validator,
)
