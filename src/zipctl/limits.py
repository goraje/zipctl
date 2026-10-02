"""Resource budgets applied before extraction policies can run."""

from dataclasses import dataclass, fields
from typing import cast


class ArchiveResourceLimitError(Exception):
    """An archive exceeded a parser or decoder resource budget."""


@dataclass(frozen=True)
class ArchiveLimits:
    """Optional byte/count limits; ``None`` disables the corresponding budget.

    Metadata counts encoded names, extra fields and comments, including the
    archive comment. Decoder budgets cover built-in LZMA and Zstandard methods;
    custom registry entries are responsible for their own memory use.
    Zstandard windows must be powers of two between 1 KiB and 2 GiB.
    """

    max_entries: int | None = None
    max_directory_bytes: int | None = None
    max_metadata_bytes: int | None = None
    max_lzma_dictionary_bytes: int | None = 1 << 30
    max_zstd_window_bytes: int | None = None

    def __post_init__(self) -> None:
        for field in fields(self):
            value = cast(object, getattr(self, field.name))
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"{field.name} must be a non-negative integer or None")
        window = self.max_zstd_window_bytes
        if window is not None and (
            window < 1024 or window > 1 << 31 or window & (window - 1)
        ):
            raise ValueError(
                "max_zstd_window_bytes must be a power of two from 1 KiB to 2 GiB"
            )

    def check(self, field: str, actual: int) -> None:
        limit = cast(int | None, getattr(self, field))
        if limit is not None and actual > limit:
            raise ArchiveResourceLimitError(f"{field}: {actual} exceeds limit {limit}")
