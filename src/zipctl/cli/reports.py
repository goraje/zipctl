"""The ``--json`` documents the commands print: a contract, key by key.

The commands build each document as one of these, so a type checker sees a
key added, dropped or renamed.  Library dataclasses never reach a document
as they are: a field added to one must not change the command's output.
"""

from __future__ import annotations

from typing import TypedDict

from zipctl.zipfile.policy import ExtractViolation

__all__ = [
    "CheckMember",
    "CheckPasswordReport",
    "CopyMember",
    "CopyReport",
    "CreateReport",
    "CreatedMember",
    "DryRunReport",
    "ErrorReport",
    "ExtractMember",
    "ExtractReport",
    "ExtractResult",
    "InspectMember",
    "InspectReport",
    "Inspection",
    "ListMember",
    "ListReport",
    "PlannedMember",
    "PolicyFile",
    "PolicyIssue",
    "PolicyValidateReport",
    "SkippedPath",
    "VerifyMember",
    "VerifyReport",
    "Violation",
    "violation_json",
]


class ErrorReport(TypedDict):
    ok: bool
    error: str
    code: int
    details: list[str]


# list


class ListMember(TypedDict):
    name: str
    directory: bool
    is_symlink: bool
    size: int
    compressed_size: int
    modified: str
    compression: str
    encryption: str
    crc32: str | None  # None where AE-2 does not store it
    mode: str | None
    comment: str


class ListReport(TypedDict):
    ok: bool
    archive: str
    comment: str
    member_count: int
    members: list[ListMember]


# test


class VerifyMember(TypedDict):
    name: str
    status: str
    detail: str | None


class VerifyReport(TypedDict):
    ok: bool
    archive: str
    tested: int
    failed: int
    members: list[VerifyMember]


# check-password


class CheckMember(TypedDict):
    name: str
    status: str


class CheckPasswordReport(TypedDict):
    ok: bool
    archive: str
    full: bool
    encrypted: int
    accepted: int
    rejected: int
    corrupt: int
    members: list[CheckMember]


# create


class CreatedMember(TypedDict):
    name: str
    directory: bool
    is_symlink: bool
    size: int
    compressed_size: int
    compression: str | None
    encryption: str


class PlannedMember(TypedDict):
    name: str
    directory: bool
    is_symlink: bool
    compression: str | None
    encryption: str


class SkippedPath(TypedDict):
    path: str
    reason: str


class CreateReport(TypedDict):
    ok: bool
    archive: str
    appended: bool
    file_count: int
    directory_count: int
    bytes_in: int
    bytes_out: int
    members: list[CreatedMember]
    skipped: list[SkippedPath]
    unused_excludes: list[str]


class DryRunReport(TypedDict):
    ok: bool
    archive: str
    dry_run: bool
    appended: bool
    file_count: int
    directory_count: int
    members: list[PlannedMember]
    skipped: list[SkippedPath]
    unused_excludes: list[str]


# encrypt, decrypt and rewrite


class CopyMember(TypedDict):
    name: str
    directory: bool
    size: int
    compression: str | None
    encryption_before: str
    encryption_after: str


class CopyReport(TypedDict):
    ok: bool
    input: str
    output: str
    verified: bool
    file_count: int
    directory_count: int
    encrypted_count: int
    members: list[CopyMember]


# extract and inspect


class Violation(TypedDict):
    member: str
    code: str
    message: str
    action: str
    target: str | None


def violation_json(violation: ExtractViolation) -> Violation:
    return {
        "member": violation.member,
        "code": violation.code,
        "message": violation.message,
        "action": violation.action.value,
        "target": None if violation.target is None else str(violation.target),
    }


class ExtractMember(TypedDict):
    member: str
    status: str
    target: str | None
    is_directory: bool
    compressed_size: int
    uncompressed_size: int
    compression_ratio: float | None
    bytes_written: int
    violations: list[Violation]
    overwritten: bool


class ExtractResult(TypedDict):
    destination: str
    members: list[ExtractMember]
    violations: list[Violation]
    extracted_count: int
    skipped_count: int
    failed_count: int
    bytes_written: int
    preview_only: bool
    previewed_count: int


class ExtractReport(TypedDict):
    ok: bool
    archive: str
    destination: str
    policy: bool
    dry_run: bool
    result: ExtractResult


class InspectMember(TypedDict):
    member: str
    target: str | None
    is_directory: bool
    compressed_size: int
    uncompressed_size: int
    compression_ratio: float | None
    encrypted: bool
    is_symlink: bool
    is_special_file: bool
    violations: list[Violation]
    assessed: bool


class Inspection(TypedDict):
    total_entries: int
    total_compressed_size: int
    total_uncompressed_size: int
    members: list[InspectMember]
    duplicate_targets: list[str]
    suspicious_paths: list[str]
    encrypted_members: list[str]
    large_members: list[str]
    compress_ratio_outliers: list[str]
    symlinks: list[str]
    special_files: list[str]
    warnings: list[Violation]
    violations: list[Violation]
    member_count_over_limit: bool


class InspectReport(TypedDict):
    ok: bool
    archive: str
    destination: str
    inspection: Inspection


# policy validate


class PolicyIssue(TypedDict):
    path: str
    message: str


class PolicyFile(TypedDict):
    file: str
    valid: bool
    issues: list[PolicyIssue]


class PolicyValidateReport(TypedDict):
    ok: bool
    files: list[PolicyFile]
