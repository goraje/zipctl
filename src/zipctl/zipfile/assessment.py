"""Typed models for metadata assessment and extraction coordination."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from zipctl.compression import Registry
from zipctl.zipfile.policy import ExtractPolicy, ExtractViolation, MemberAssessment


@dataclass(frozen=True)
class ExtractionContext:
    """Immutable per-extraction context shared by validators and materializers."""

    destination: Path
    policy_root: Path
    registry: Registry
    policy: ExtractPolicy


def target_key(target: Path) -> str:
    """What *target* is called on a filesystem that ignores case or Unicode form.

    ``a.txt`` and ``A.txt``, or ``é`` composed and decomposed, are one file on
    APFS, NTFS and casefolded ext4, so they count as the same target.
    """
    return unicodedata.normalize("NFC", str(target)).casefold()


@dataclass
class ValidationState:
    """Mutable archive-wide state used while assessing members."""

    total_declared: int = 0
    total_compressed: int = 0
    targets: dict[str, str] = field(default_factory=dict)  # by target_key
    # Recorded whether or not the policy rejects duplicates.
    duplicate_targets: list[Path] = field(default_factory=list)
    symlinks: set[str] = field(default_factory=set)  # by target_key
    files: set[str] = field(default_factory=set)  # other non-directories, likewise
    # by target_key: the first member that needs it as a directory
    parents: dict[str, str] = field(default_factory=dict)
    # Disk parents by exact path (a case-sensitive filesystem may hold "A" and
    # "a"): their file type, 0 when missing.
    file_types: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class ArchiveAssessment:
    """Immutable archive-wide result shared by inspection and extraction."""

    destination: Path
    members: tuple[MemberAssessment, ...]
    violations: tuple[ExtractViolation, ...]
    total_compressed_size: int
    total_uncompressed_size: int
    duplicate_targets: tuple[Path, ...]
