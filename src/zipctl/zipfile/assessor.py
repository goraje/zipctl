"""Metadata-only assessment of archive members against an extraction policy."""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import replace
from pathlib import Path

from zipctl.compression import Registry, registry
from zipctl.zipfile.assessment import (
    ArchiveAssessment,
    ExtractionContext,
    ValidationState,
)
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.policy import (
    ExtractPolicy,
    ExtractViolation,
    MemberAssessment,
    ViolationAction,
    normalized_destination,
    resolve_rule,
)
from zipctl.zipfile.validators import (
    EXTRACT_VALIDATORS,
    ValidatorParams,
    entry_type,
    resolve_extract_target,
)

__all__ = [
    "assess_archive",
    "assess_member",
    "entry_count_violation",
    "policy_root",
]

# Findings that can never be downgraded to warnings, regardless of policy.
_HARD_VIOLATIONS = frozenset(
    {
        "absolute_path",
        "windows_drive_path",
        "windows_path",
        "parent_traversal",
        "outside_root",
        "symlink",
        "special_file",
        "unsafe_destination",
    }
)


def entry_count_violation(count: int, policy: ExtractPolicy) -> ExtractViolation | None:
    """Return the archive-level ``max_entries`` finding for *count* entries."""
    rule = resolve_rule(policy.max_entries, policy.on_violation)
    if rule.value is None or count <= rule.value:
        return None
    return ExtractViolation(
        "<archive>",
        "max_entries",
        f"archive contains {count} entries, limit is {rule.value}",
        rule.action,
    )


def _escalate_hard_violations(
    violations: Iterable[ExtractViolation],
) -> list[ExtractViolation]:
    """Turn WARN into ERROR for findings that must never be soft-failed."""
    return [
        replace(violation, action=ViolationAction.ERROR)
        if violation.code in _HARD_VIOLATIONS
        and violation.action == ViolationAction.WARN
        else violation
        for violation in violations
    ]


def assess_member(
    info: ZipInfo,
    destination: Path,
    policy_root: Path,
    policy: ExtractPolicy,
    state: ValidationState,
    compression_registry: Registry = registry,
) -> MemberAssessment:
    """Validate one member, updating the archive-wide *state*."""
    try:
        target, _drive, _parts = resolve_extract_target(info, destination)
        target.resolve()
    except (OSError, ValueError, RuntimeError) as exc:
        return MemberAssessment(
            info,
            None,
            (
                ExtractViolation(
                    info.filename, "unsafe_destination", str(exc), ViolationAction.ERROR
                ),
            ),
            *entry_type(info),
        )
    context = ExtractionContext(destination, policy_root, compression_registry, policy)
    params = ValidatorParams(info, target, context, state)
    violations = [v for check in EXTRACT_VALIDATORS for v in check(params)]
    return MemberAssessment(
        info,
        target,
        tuple(_escalate_hard_violations(violations)),
        *entry_type(info),
    )


def policy_root(policy: ExtractPolicy, destination: Path) -> Path:
    """The directory *policy* confines extraction to: its root, else *destination*.

    Symlinks in it are resolved, as they are in the targets compared with it.
    """
    return normalized_destination(policy.destination_root or destination).resolve()


def assess_archive(
    infos: Sequence[ZipInfo],
    path: str | os.PathLike[str] | None,
    policy: ExtractPolicy | None,
    compression_registry: Registry = registry,
) -> ArchiveAssessment:
    """Assess every member of an archive without touching its payloads.

    An entry-count limit whose action is SKIP or ERROR stops assessment at
    the limit: the members past it are marked unassessed and not validated.
    """
    policy = policy or ExtractPolicy()
    destination = normalized_destination(path or os.getcwd())
    root = policy_root(policy, destination)
    count_violation = entry_count_violation(len(infos), policy)
    limit: int | None = None
    violations: list[ExtractViolation] = []
    if count_violation is not None:
        violations.append(count_violation)
        if count_violation.action != ViolationAction.WARN:
            limit = resolve_rule(policy.max_entries, policy.on_violation).value
    state = ValidationState()
    members: list[MemberAssessment] = []
    for index, info in enumerate(infos):
        if limit is not None and index >= limit:
            assessment = MemberAssessment(info, None, (), *entry_type(info), False)
        else:
            state.total_declared += info.file_size
            state.total_compressed += info.compress_size
            assessment = assess_member(
                info, destination, root, policy, state, compression_registry
            )
        members.append(assessment)
        violations.extend(assessment.violations)
    return ArchiveAssessment(
        destination,
        tuple(members),
        tuple(violations),
        state.total_compressed,
        state.total_declared,
        tuple(dict.fromkeys(state.duplicate_targets)),
    )
