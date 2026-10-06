"""Extraction runs: assess every member, then materialize what the policy allows."""

from __future__ import annotations

import os
import warnings
from collections.abc import Callable, Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import IO, Protocol, TypeAlias

from zipctl.compression import Registry, registry
from zipctl.exceptions import BadZipFile, PasswordError
from zipctl.limits import ArchiveResourceLimitError
from zipctl.zipfile.assessment import (
    ArchiveAssessment,
    ExtractionContext,
    ValidationState,
    target_key,
)
from zipctl.zipfile.assessor import assess_archive, policy_root
from zipctl.zipfile.exceptions import (
    ExtractionFailure,
    ExtractionQuotaExceeded,
    ExtractionSecurityError,
)
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.materialize import ByteQuota, StagedEntry, staged
from zipctl.zipfile.policy import (
    ExtractMemberResult,
    ExtractPolicy,
    ExtractResult,
    ExtractViolation,
    MemberAssessment,
    MemberStatus,
    OverwritePolicy,
    ViolationAction,
    compression_ratio,
    normalized_destination,
    resolve_rule,
)
from zipctl.zipfile.progress import (
    ProgressCallback,
    ProgressReporter,
    propagate_callback_errors,
)
from zipctl.zipfile.secure_fs import SecureExtractionRoot, sync_directory
from zipctl.zipfile.shared import ReadWriteMode, StrPath, user_stacklevel
from zipctl.zipfile.validators import (
    TARGET_NAME_VALIDATORS,
    ValidatorParams,
    member_target_name,
    name_suffixes,
)

__all__ = ["PasswordProvider", "extract_members_with_policy"]

# What one member's content can make its extraction fail with; anything else
# is a bug and propagates.  Unsupported methods and flags are refused during
# assessment already; a decoder that needs more memory than the limits allow
# (a zstd window, an LZMA dictionary) is only found once the data is read.
_MATERIALIZATION_ERRORS = (
    OSError,
    BadZipFile,
    PasswordError,
    ExtractionFailure,
    ArchiveResourceLimitError,
    NotImplementedError,
)


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


def _refused(info: ZipInfo, target: Path | None) -> ExtractViolation:
    return ExtractViolation(
        info.filename,
        "archive_refused",
        "not extracted: the archive was refused",
        ViolationAction.SKIP,
        target,
    )


def _unwritten_result(
    assessment: ArchiveAssessment,
    policy: ExtractPolicy,
    reporter: ProgressReporter | None,
    violations: list[ExtractViolation],
    rejection: ExtractViolation | None,
) -> ExtractResult:
    """Result for an archive refused as a whole; nothing is written.

    A *rejection* (an entry-count ERROR) fails every member with only that
    finding.  Otherwise the members with errors fail, the rest are skipped,
    and every member's findings join the run's *violations*.
    """
    results: list[ExtractMemberResult] = []
    for index, member in enumerate(assessment.members):
        info, target, found = member.info, member.target, member.violations
        if rejection is not None:
            status, target, found = MemberStatus.FAILED, None, (rejection,)
        elif member.has_errors:
            status = MemberStatus.FAILED
        else:
            status = MemberStatus.SKIPPED
            if member.assessed:
                found += (_refused(info, target),)
        results.append(_member_result(info, status, target, 0, found))
        if reporter is not None:
            reporter.start(index, info)
            reporter.finish(status, 0)
    if rejection is None:
        violations.extend(v for result in results for v in result.violations)
    return _summarise(assessment.destination, results, violations, policy)


class _Extraction:
    """The running totals, limits and rename numbering of one extraction run."""

    def __init__(
        self,
        destination: Path,
        policy_root: Path,
        policy: ExtractPolicy,
        open_member: Callable[[ZipInfo], IO[bytes]],
        reporter: ProgressReporter | None,
        compression_registry: Registry,
        assessments: Sequence[MemberAssessment],
    ) -> None:
        self.destination: Path = destination
        self.policy_root: Path = policy_root
        self.policy: ExtractPolicy = policy
        self.open_member: Callable[[ZipInfo], IO[bytes]] = open_member
        self.reporter: ProgressReporter | None = reporter
        self.state: ValidationState = ValidationState()
        self.registry: Registry = compression_registry
        self.assessments: Sequence[MemberAssessment] = assessments
        self.total_written: int = 0
        self.rename_counters: dict[str, int] = {}
        # A renamed member must not take a name another member is headed for,
        # as its target or as a directory on the way there.
        self.planned_targets: set[str] = {
            target_key(path)
            for a in assessments
            if a.target is not None
            for path in (a.target, *a.target.parents)
        }
        self.touched_directories: set[str] = set()
        # The destination, opened by the first member written and closed with
        # the run: every member's parents are then opened below the same
        # directory, however its path changes meanwhile.
        self.root: SecureExtractionRoot | None = None
        self.cleanup: ExitStack = ExitStack()
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

    def sync_directories(self) -> None:
        """Make the renames durable: each file was fsynced before its own."""
        for directory in sorted(self.touched_directories):
            sync_directory(directory)

    def process(self, index: int, info: ZipInfo) -> ExtractMemberResult:
        assessment = self.assessments[index]
        target = assessment.target
        member_violations = assessment.violations

        if assessment.has_errors:
            return _member_result(
                info, MemberStatus.FAILED, target, 0, member_violations
            )
        if assessment.should_skip:
            return _member_result(
                info, MemberStatus.SKIPPED, target, 0, member_violations
            )
        for violation in member_violations:
            warnings.warn(violation.message, stacklevel=user_stacklevel())

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
        action = ViolationAction.ERROR
        try:
            return self._materialize(info, target, member_violations)
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

        violation = ExtractViolation(info.filename, code, message, action, target)
        return _member_result(
            info,
            MemberStatus.SKIPPED
            if action == ViolationAction.SKIP
            else MemberStatus.FAILED,
            target,
            0,
            member_violations + (violation,),
        )

    def _materialize(
        self,
        info: ZipInfo,
        target: Path,
        found: tuple[ExtractViolation, ...],
    ) -> ExtractMemberResult:
        """Stage *info* beside *target*, then publish it there or renamed."""
        _, parts = member_target_name(info.filename)
        if not parts:
            if info.is_dir():
                # "./" or "/": the destination itself, which already exists.
                return _member_result(
                    info, MemberStatus.EXTRACTED, self.destination, 0, found
                )
            raise ExtractionSecurityError("Empty file name")
        quota = ByteQuota(
            self.member_limit,
            self.total_limit,
            self.total_written,
            None if self.reporter is None else self.reporter.advance,
        )
        overwrite = self.policy.overwrite_policy
        if self.root is None:
            self.root = self.cleanup.enter_context(
                SecureExtractionRoot(self.destination)
            )
        with staged(
            info,
            target,
            self.root,
            lambda: self.open_member(info),
            quota,
            overwrite,
            self.policy.fsync_files,
        ) as entry:
            if entry.temp is None:
                return _member_result(
                    info, MemberStatus.EXTRACTED, target, 0, found, entry.existed
                )
            if self.policy.fsync_files:
                self.touched_directories.add(os.path.dirname(target))
            if overwrite != OverwritePolicy.RENAME:
                overwritten = entry.publish(target)
                return _member_result(
                    info, MemberStatus.EXTRACTED, target, entry.size, found, overwritten
                )
            return self._publish_renamed(info, target, entry, found)

    def _publish_renamed(
        self,
        info: ZipInfo,
        target: Path,
        entry: StagedEntry,
        found: tuple[ExtractViolation, ...],
    ) -> ExtractMemberResult:
        """Publish at the first free name of *target*, ``name.1.tar.gz``, ...

        The counter goes before the whole chain of suffixes, so a renamed
        target still matches the extension rules its original name matched.

        Each target's numbering resumes where an earlier member of the run
        stopped, names other members of the run need (as targets or parent
        directories) are skipped, and every renamed target is validated before
        it is used.
        """
        key = os.fspath(target)
        suffix = "".join(name_suffixes(target.name))
        stem = target.name[: len(target.name) - len(suffix)]
        counter = self.rename_counters.get(key, 0)
        while True:
            candidate = (
                target
                if counter == 0
                else target.with_name(f"{stem}.{counter}{suffix}")
            )
            if counter and target_key(candidate) in self.planned_targets:
                counter += 1
                continue
            warned: tuple[ExtractViolation, ...] = ()
            if counter:
                findings = self._validate_candidate(info, candidate)
                if any(v.action != ViolationAction.WARN for v in findings):
                    status = (
                        MemberStatus.FAILED
                        if any(v.action == ViolationAction.ERROR for v in findings)
                        else MemberStatus.SKIPPED
                    )
                    return _member_result(info, status, candidate, 0, found + findings)
                warned = findings
            try:
                entry.publish(candidate)
            except FileExistsError:
                counter += 1
                continue
            self.rename_counters[key] = counter + 1
            # only the candidate actually used reports its warnings
            for violation in warned:
                warnings.warn(violation.message, stacklevel=user_stacklevel())
            return _member_result(
                info, MemberStatus.EXTRACTED, candidate, entry.size, found + warned
            )

    def _validate_candidate(
        self, info: ZipInfo, target: Path
    ) -> tuple[ExtractViolation, ...]:
        """Return the findings of the rules a renamed *target* can change."""
        params = ValidatorParams(
            info,
            target,
            ExtractionContext(
                self.destination, self.policy_root, self.registry, self.policy
            ),
            self.state,
        )
        return tuple(v for rule in TARGET_NAME_VALIDATORS for v in rule(params))


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


def _run(
    infos: Sequence[ZipInfo],
    destination: Path,
    policy: ExtractPolicy,
    open_member: Callable[[ZipInfo], IO[bytes]],
    reporter: ProgressReporter | None,
    compression_registry: Registry,
) -> ExtractResult:
    assessment = assess_archive(infos, destination, policy, compression_registry)
    destination = assessment.destination
    # The entry-count limit applies to the archive as a whole: ERROR rejects
    # everything before any file is written, SKIP keeps only the first N
    # entries (the assessment skips the rest), and WARN just reports it.
    count_violation = next(
        (v for v in assessment.violations if v.code == "max_entries"), None
    )
    # The run's violations: the archive-level findings, then every member's.
    violations: list[ExtractViolation] = (
        [] if count_violation is None else [count_violation]
    )
    if count_violation is not None:
        if count_violation.action == ViolationAction.ERROR:
            return _unwritten_result(
                assessment, policy, reporter, violations, count_violation
            )
        if count_violation.action == ViolationAction.WARN:
            warnings.warn(count_violation.message, stacklevel=user_stacklevel())

    # An error finding anywhere means the archive is refused as a whole.
    if any(member.has_errors for member in assessment.members):
        return _unwritten_result(assessment, policy, reporter, violations, None)

    extraction = _Extraction(
        destination,
        policy_root(policy, destination),
        policy,
        open_member,
        reporter,
        compression_registry,
        assessment.members,
    )
    results: list[ExtractMemberResult] = []
    with extraction.cleanup:
        for index, info in enumerate(infos):
            if reporter is not None:
                reporter.start(index, info)
            result = extraction.process(index, info)
            results.append(result)
            violations.extend(result.violations)
            if reporter is not None:
                reporter.finish(result.status, result.bytes_written)
    extraction.sync_directories()
    return _summarise(destination, results, violations, policy)


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


def extract_members_with_policy(
    zf: _Archive,
    members: list[str | ZipInfo],
    path: StrPath | None,
    pwd: bytes | PasswordProvider | None,
    policy: ExtractPolicy,
    progress: ProgressCallback | None = None,
    compression_registry: Registry = registry,
) -> ExtractResult:
    """Extract *members* of *zf* under *policy*, reporting per-member outcomes.

    The archive is assessed first (see :func:`assess_archive`); only members
    whose findings permit it are written.  Failures are recorded, not raised.
    When *progress* is given, every member gets a start and a finish event.
    """
    destination = normalized_destination(path or os.getcwd())
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
        return _run(
            infos,
            destination,
            policy,
            lambda info: zf.open(info, pwd=password_for(info, pwd)),
            reporter,
            compression_registry,
        )
