"""Shapes of the ``--json`` documents the zipctl commands print.

Each ``TypedDict`` lists the keys the tests read, so indexing a parsed
document is typed instead of ``Any``.  Nothing checks a document against its
shape: the tests assert the values, and a key missing at run time is a
``KeyError`` in the test.
"""

from __future__ import annotations

import json
from typing import TypedDict, TypeVar, cast

from tests.functional.cli.support import Result
from zipctl.cli.output import JsonValue

_T = TypeVar("_T")


def load_json(result: Result, _shape: type[_T]) -> _T:
    """Parse the standard output of *result* as a document of type *_shape*."""
    return cast("_T", json.loads(result.stdout))


class ErrorReport(TypedDict):
    ok: bool
    code: int
    error: str


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
    crc32: str
    mode: str
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


class CreateMember(TypedDict):
    name: str
    directory: bool
    is_symlink: bool
    size: int
    compression: str
    encryption: str


class CreateReport(TypedDict):
    ok: bool
    archive: str
    dry_run: bool
    appended: bool
    file_count: int
    directory_count: int
    bytes_in: int
    members: list[CreateMember]
    skipped: list[JsonValue]
    unused_excludes: list[str]


# encrypt, decrypt and rewrite


class CopyMember(TypedDict):
    name: str
    directory: bool
    size: int
    compression: str
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


# extract


class Violation(TypedDict):
    code: str
    action: str


class ExtractMember(TypedDict):
    member: str
    status: str
    target: str
    bytes_written: int
    is_directory: bool
    violations: list[Violation]


class ExtractResult(TypedDict):
    extracted_count: int
    failed_count: int
    bytes_written: int
    members: list[ExtractMember]


class ExtractReport(TypedDict):
    ok: bool
    archive: str
    destination: str
    policy: bool
    dry_run: bool
    result: ExtractResult


# inspect


class InspectViolation(TypedDict):
    member: str
    code: str
    action: str


class InspectMember(TypedDict):
    member: str
    target: str
    compressed_size: int
    encrypted: bool


class Inspection(TypedDict):
    total_entries: int
    member_count_over_limit: bool
    members: list[InspectMember]
    violations: list[InspectViolation]
    duplicate_member_names: list[str]
    encrypted_members: list[str]
    symlinks: list[str]
    special_files: list[str]
    suspicious_paths: list[str]


class InspectReport(TypedDict):
    ok: bool
    archive: str
    destination: str
    inspection: Inspection


# policy


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


class PolicyShowDocument(TypedDict):
    version: int
    allowed_extensions: list[str]
