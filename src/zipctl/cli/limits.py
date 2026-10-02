"""Per-command archive budgets, set from options and carried on the Context."""

import argparse
import re
from dataclasses import fields
from typing import cast

from zipctl.limits import ArchiveLimits

DEFAULT_LIMITS = ArchiveLimits()

_UNITS = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}
_AMOUNT = re.compile(r"(\d+)\s*([kmg]?)(?:i?b)?", re.IGNORECASE)


def _budget(value: str) -> int | None:
    if value.lower() == "none":
        return None
    match = _AMOUNT.fullmatch(value.strip())
    if match is None:
        raise argparse.ArgumentTypeError(
            "expected a non-negative integer, a size such as 64MiB, or 'none'"
        )
    return int(match[1]) * _UNITS[match[2].lower()]


def _human(number: int | None) -> str:
    if number is None:
        return "none"
    for unit, size in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if number >= size and number % size == 0:
            return f"{number // size}{unit}"
    return str(number)


def add_limit_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group(
        "resource budgets",
        "Sizes take K/M/G (binary) suffixes; 'none' disables a budget.",
    )
    for field in fields(DEFAULT_LIMITS):
        default = cast(int | None, getattr(DEFAULT_LIMITS, field.name))
        group.add_argument(
            "--archive-" + field.name.replace("_", "-"),
            dest="archive_" + field.name,
            type=_budget,
            default=default,
            metavar="N|none",
            help=f"{field.name.replace('_', ' ')}. Default: {_human(default)}",
        )


def limits_from_args(args: argparse.Namespace) -> ArchiveLimits:
    return ArchiveLimits(
        **{
            field.name: cast(int | None, getattr(args, "archive_" + field.name))
            for field in fields(DEFAULT_LIMITS)
        }
    )
