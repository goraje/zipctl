"""Per-command archive budgets, also used by nested archive-opening helpers."""

import argparse
from contextvars import ContextVar
from dataclasses import fields
from typing import cast

from zipctl.limits import ArchiveLimits

DEFAULT_LIMITS = ArchiveLimits(
    max_entries=100_000,
    max_directory_bytes=64 << 20,
    max_metadata_bytes=32 << 20,
    max_lzma_dictionary_bytes=64 << 20,
    max_zstd_window_bytes=64 << 20,
)
current_limits: ContextVar[ArchiveLimits] = ContextVar(
    "archive_limits", default=DEFAULT_LIMITS
)


def _budget(value: str) -> int | None:
    if value == "none":
        return None
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "expected a non-negative integer or 'none'"
        ) from None
    if number < 0:
        raise argparse.ArgumentTypeError("budget must be non-negative")
    return number


def add_limit_options(parser: argparse.ArgumentParser) -> None:
    for field in fields(DEFAULT_LIMITS):
        default = cast(int | None, getattr(DEFAULT_LIMITS, field.name))
        parser.add_argument(
            "--archive-" + field.name.replace("_", "-"),
            dest="archive_" + field.name,
            type=_budget,
            default=default,
            metavar="N|none",
            help=f"archive resource budget ({field.name}). Default: {default}",
        )


def limits_from_args(args: argparse.Namespace) -> ArchiveLimits:
    return ArchiveLimits(
        **{
            field.name: cast(int | None, getattr(args, "archive_" + field.name))
            for field in fields(DEFAULT_LIMITS)
        }
    )
