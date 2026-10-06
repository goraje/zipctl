"""Command-line options several commands share."""

from __future__ import annotations

import argparse

__all__ = ["add_output_options"]


def add_output_options(
    parser: argparse.ArgumentParser,
    *,
    verbose_help: str | None = None,
    quiet: bool = False,
) -> None:
    """Add ``--json``, plus ``-v`` and ``-q`` when asked for.

    *verbose_help* is the help text of ``-v`` (giving it adds ``-v``); ``quiet=True``
    adds ``-q``.  When both are added they exclude each other.
    """
    if verbose_help is not None or quiet:  # argparse rejects an empty group
        verbosity = parser.add_mutually_exclusive_group()
        if verbose_help is not None:
            verbosity.add_argument(
                "-v", "--verbose", action="store_true", help=verbose_help
            )
        if quiet:
            verbosity.add_argument(
                "-q", "--quiet", action="store_true", help="print only errors"
            )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
