"""Policy-driven extraction: assess each member, then materialize what is allowed."""

from __future__ import annotations

import warnings
from collections.abc import Callable, Sequence
from pathlib import Path

from ziplet.exceptions import BadZipFile
from ziplet.zipfile.assessment import ValidationState
from ziplet.zipfile.assessor import assess_member, entry_count_violation
from ziplet.zipfile.exceptions import ExtractionFailure, ExtractionQuotaExceeded
from ziplet.zipfile.extract import (
    ExtractMemberResult,
    ExtractPolicy,
    ExtractResult,
    ExtractViolation,
    MemberStatus,
    OverwritePolicy,
    ViolationAction,
    compression_ratio,
    resolve_rule,
)
from ziplet.zipfile.info import ZipInfo
from ziplet.zipfile.materialize import ExtractionQuota, MaterializationResult
from ziplet.zipfile.progress import ProgressReporter

__all__ = ["Materialize", "extract_with_policy"]

Materialize = Callable[
    [ZipInfo, Path, ExtractionQuota, ProgressReporter | None], MaterializationResult
]

_MATERIALIZATION_ERRORS = (
    OSError,
    ValueError,
    BadZipFile,
    RuntimeError,
    ExtractionFailure,
)

# Depth of the frame that called ``ZipFile.extract``/``extractall``, so warnings
# point at the user's code rather than at library internals.
_WARN_STACKLEVEL = 4


def _member_result(
    info: ZipInfo,
    status: MemberStatus,
    target: Path | None,
    written: int,
    violations: tuple[ExtractViolation, ...],
    overwritten: bool = False,
) -> ExtractMemberResult:
    return ExtractMemberResult(
        info.filename,
        status,
        target,
        info.is_dir(),
        info.compress_size,
        info.file_size,
        compression_ratio(info),
        written,
        violations,
        overwritten,
    )


def _unique_target(target: Path, policy: ExtractPolicy) -> Path:
    """Return *target*, or a numbered sibling when renaming on conflict."""
    if policy.overwrite_policy != OverwritePolicy.RENAME or not target.exists():
        return target
    counter = 1
    candidate = target
    while candidate.exists():
        candidate = target.with_name(f"{target.name}.{counter}")
        counter += 1
    return candidate


def _rejected_result(
    infos: Sequence[ZipInfo],
    destination: Path,
    policy: ExtractPolicy,
    violation: ExtractViolation,
) -> ExtractResult:
    """Result for an archive rejected as a whole; nothing was extracted."""
    members = tuple(
        _member_result(info, MemberStatus.FAILED, None, 0, (violation,))
        for info in infos
    )
    return ExtractResult(
        destination,
        members,
        (violation,),
        0,
        0,
        len(members),
        0,
        policy.preview_only,
    )


class _Extraction:
    """The running totals and limits of one :func:`extract_with_policy` call."""

    def __init__(
        self,
        destination: Path,
        policy_root: Path,
        policy: ExtractPolicy,
        materialize: Materialize,
        reporter: ProgressReporter | None,
        entry_limit: int | None,
        violations: list[ExtractViolation],
    ) -> None:
        self.destination: Path = destination
        self.policy_root: Path = policy_root
        self.policy: ExtractPolicy = policy
        self.materialize: Materialize = materialize
        self.reporter: ProgressReporter | None = reporter
        self.entry_limit: int | None = entry_limit
        self.violations: list[ExtractViolation] = violations
        self.state: ValidationState = ValidationState()
        self.total_written: int = 0
        self.member_limit: int | None = resolve_rule(
            policy.max_member_size, policy.on_violation
        ).value
        self.total_limit: int | None = resolve_rule(
            policy.max_total_uncompressed_size, policy.on_violation
        ).value

    def process(self, index: int, info: ZipInfo) -> ExtractMemberResult:
        if self.entry_limit is not None and index >= self.entry_limit:
            return _member_result(info, MemberStatus.SKIPPED, None, 0, ())
        self.state.total_declared += info.file_size
        self.state.total_compressed += info.compress_size
        assessment = assess_member(
            info, self.destination, self.policy_root, self.policy, self.state
        )
        target = assessment.target
        member_violations = assessment.violations
        self.violations.extend(member_violations)

        if assessment.has_errors:
            return _member_result(
                info, MemberStatus.FAILED, target, 0, member_violations
            )
        if assessment.should_skip:
            return _member_result(
                info, MemberStatus.SKIPPED, target, 0, member_violations
            )
        for violation in member_violations:
            warnings.warn(violation.message, stacklevel=_WARN_STACKLEVEL)

        if self.policy.preview_only:
            return _member_result(
                info, MemberStatus.PREVIEWED, target, 0, member_violations
            )

        assert target is not None
        result = self._write(
            info, _unique_target(target, self.policy), member_violations
        )
        self.total_written += result.bytes_written
        return result

    def _write(
        self,
        info: ZipInfo,
        target: Path,
        member_violations: tuple[ExtractViolation, ...],
    ) -> ExtractMemberResult:
        was_existing = target.exists()
        quota = ExtractionQuota(self.member_limit, self.total_limit, self.total_written)
        try:
            materialized = self.materialize(info, target, quota, self.reporter)
        except ExtractionQuotaExceeded as exc:
            code, message = exc.code, str(exc)
        except _MATERIALIZATION_ERRORS as exc:
            code, message = "extraction_error", str(exc)
        else:
            return _member_result(
                info,
                MemberStatus.EXTRACTED,
                materialized.target,
                materialized.bytes_written,
                member_violations,
                was_existing,
            )

        violation = ExtractViolation(
            info.filename, code, message, ViolationAction.ERROR, target
        )
        self.violations.append(violation)
        return _member_result(
            info, MemberStatus.FAILED, target, 0, member_violations + (violation,)
        )


def _summarise(
    destination: Path,
    results: list[ExtractMemberResult],
    violations: list[ExtractViolation],
    policy: ExtractPolicy,
) -> ExtractResult:
    extracted = sum(r.status == MemberStatus.EXTRACTED for r in results)
    skipped = sum(r.status == MemberStatus.SKIPPED for r in results)
    previewed = sum(r.status == MemberStatus.PREVIEWED for r in results)
    failed = sum(r.status == MemberStatus.FAILED for r in results)
    if any(v.action == ViolationAction.ERROR for v in violations):
        failed = max(failed, 1)
    return ExtractResult(
        destination,
        tuple(results),
        tuple(violations),
        extracted,
        skipped,
        failed,
        sum(r.bytes_written for r in results),
        policy.preview_only,
        previewed,
    )


def extract_with_policy(
    infos: Sequence[ZipInfo],
    destination: Path,
    policy_root: Path,
    policy: ExtractPolicy,
    materialize: Materialize,
    reporter: ProgressReporter | None = None,
) -> ExtractResult:
    """Extract *infos* under *policy*, reporting per-member outcomes.

    Each member is assessed first; only members whose findings permit it are
    passed to *materialize*.  Failures are recorded, not raised.  When a
    *reporter* is given, every member gets a start and a finish notification.
    """
    violations: list[ExtractViolation] = []

    # The entry-count limit applies to the archive as a whole: ERROR rejects
    # everything before any file is written, SKIP keeps only the first N
    # entries, and WARN just reports it.
    entry_limit: int | None = None
    count_violation = entry_count_violation(len(infos), policy)
    if count_violation is not None:
        violations.append(count_violation)
        if count_violation.action == ViolationAction.ERROR:
            return _rejected_result(infos, destination, policy, count_violation)
        if count_violation.action == ViolationAction.SKIP:
            entry_limit = resolve_rule(policy.max_entries, policy.on_violation).value
        else:
            warnings.warn(count_violation.message, stacklevel=_WARN_STACKLEVEL)

    extraction = _Extraction(
        destination, policy_root, policy, materialize, reporter, entry_limit, violations
    )
    results: list[ExtractMemberResult] = []
    for index, info in enumerate(infos):
        if reporter is not None:
            reporter.start(index, info)
        result = extraction.process(index, info)
        results.append(result)
        if reporter is not None:
            reporter.finish(result.status, result.bytes_written)
    return _summarise(destination, results, violations, policy)
