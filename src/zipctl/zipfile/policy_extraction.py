"""Policy-driven extraction: assess each member, then materialize what is allowed."""

from __future__ import annotations

import warnings
from collections.abc import Callable, Sequence
from pathlib import Path

from zipctl.exceptions import BadZipFile, PasswordError
from zipctl.zipfile.assessment import ExtractionContext, ValidationState
from zipctl.zipfile.assessor import assess_member, entry_count_violation
from zipctl.zipfile.exceptions import ExtractionFailure, ExtractionQuotaExceeded
from zipctl.zipfile.extract import (
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
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.materialize import ExtractionQuota, MaterializationResult
from zipctl.zipfile.progress import ProgressReporter
from zipctl.zipfile.validators import (
    ValidatorParams,
    check_custom_validator,
    check_extension_allowed,
    check_extension_blocked,
)

__all__ = ["Materialize", "extract_with_policy"]

Materialize = Callable[
    [ZipInfo, Path, ExtractionQuota, ProgressReporter | None], MaterializationResult
]

# What one member's extraction can fail with; anything else is not about the
# member (a missing codec backend, a resource budget, a bug) and propagates.
_MATERIALIZATION_ERRORS = (
    OSError,
    BadZipFile,
    PasswordError,
    ExtractionFailure,
)

# Depth of the frame that called ``ZipFile.extract``/``extractall``, so warnings
# point at the user's code rather than at library internals.
_WARN_STACKLEVEL = 4


class _CandidateRejected(Exception):
    def __init__(self, violations: tuple[ExtractViolation, ...]) -> None:
        super().__init__("Renamed extraction target violates policy")
        self.violations: tuple[ExtractViolation, ...] = violations


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
        member_rule = resolve_rule(policy.max_member_size, policy.on_violation)
        total_rule = resolve_rule(
            policy.max_total_uncompressed_size, policy.on_violation
        )
        self.member_limit: int | None = (
            None if member_rule.action == ViolationAction.WARN else member_rule.value
        )
        self.total_limit: int | None = (
            None if total_rule.action == ViolationAction.WARN else total_rule.value
        )

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
        result = self._write(info, target, member_violations)
        self.total_written += result.bytes_written
        return result

    def _write(
        self,
        info: ZipInfo,
        target: Path,
        member_violations: tuple[ExtractViolation, ...],
    ) -> ExtractMemberResult:
        quota = ExtractionQuota(
            self.member_limit,
            self.total_limit,
            self.total_written,
            self.state.created_directories,
            lambda candidate: self._validate_candidate(info, candidate),
        )
        action = ViolationAction.ERROR
        try:
            materialized = self.materialize(info, target, quota, self.reporter)
        except _CandidateRejected as exc:
            self.violations.extend(exc.violations)
            status = (
                MemberStatus.FAILED
                if any(v.action == ViolationAction.ERROR for v in exc.violations)
                else MemberStatus.SKIPPED
            )
            return _member_result(
                info,
                status,
                exc.violations[0].target,
                0,
                member_violations + exc.violations,
            )
        except FileExistsError as exc:
            code, message = "overwrite", str(exc)
            if self.policy.overwrite_policy == OverwritePolicy.SKIP:
                action = ViolationAction.SKIP
        except ExtractionQuotaExceeded as exc:
            code, message = exc.code, str(exc)
            field = (
                self.policy.max_member_size
                if code == "actual_member_size"
                else self.policy.max_total_uncompressed_size
            )
            action = resolve_rule(field, self.policy.on_violation).action
        except _MATERIALIZATION_ERRORS as exc:
            code, message = "extraction_error", str(exc)
        else:
            return _member_result(
                info,
                MemberStatus.EXTRACTED,
                materialized.target,
                materialized.bytes_written,
                member_violations,
                materialized.overwritten,
            )

        violation = ExtractViolation(info.filename, code, message, action, target)
        self.violations.append(violation)
        return _member_result(
            info,
            MemberStatus.SKIPPED
            if action == ViolationAction.SKIP
            else MemberStatus.FAILED,
            target,
            0,
            member_violations + (violation,),
        )

    def _validate_candidate(self, info: ZipInfo, target: Path) -> None:
        params = ValidatorParams(
            info,
            target,
            ExtractionContext(self.destination, self.policy_root, None, self.policy),
            self.state,
        )
        violations = tuple(
            v
            for validator in (
                check_extension_allowed,
                check_extension_blocked,
                check_custom_validator,
            )
            for v in validator(params)
        )
        if any(v.action != ViolationAction.WARN for v in violations):
            raise _CandidateRejected(violations)
        self.violations.extend(violations)
        for violation in violations:
            warnings.warn(violation.message, stacklevel=_WARN_STACKLEVEL)


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
