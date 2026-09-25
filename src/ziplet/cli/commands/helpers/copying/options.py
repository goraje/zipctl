"""The command-line side of the copying commands: arguments and path checks."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass

from ziplet.cli.commands.helpers.output_options import (
    OutputOptions,
    add_output_options,
)
from ziplet.cli.errors import CliError, UsageError
from ziplet.cli.output import printable


@dataclass(frozen=True)
class CopyJob:
    """What :func:`add_copy_options` collects: the files and how to report."""

    input: str
    output: str
    force: bool
    verify: bool
    report: OutputOptions


def copy_job(args: argparse.Namespace) -> CopyJob:
    return CopyJob(
        args.input,
        args.output,
        args.force,
        not args.no_verify,
        OutputOptions.from_args(args),
    )


def check_paths(job: CopyJob) -> None:
    """Refuse an output that is the input, or that exists without ``--force``."""
    try:
        same = os.path.samefile(job.input, job.output)
    except OSError:
        same = False
    if same:
        raise UsageError(
            f"{printable(job.output)} is the input archive; ziplet never rewrites "
            "an archive in place (write a new file, then move it over the original)",
        )
    if os.path.lexists(job.output) and not job.force:
        raise CliError(
            f"{printable(job.output)} already exists (use --force to replace it)"
        )


def add_copy_options(parser: argparse.ArgumentParser) -> None:
    """The arguments every copying command takes."""
    parser.add_argument("input", metavar="INPUT", help="the archive to read")
    parser.add_argument(
        "output", metavar="OUTPUT", help="the new archive (never the input itself)"
    )
    parser.add_argument(
        "--force", action="store_true", help="replace OUTPUT if it exists"
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="skip reading OUTPUT back before moving it into place",
    )
    add_output_options(parser, verbose_help="list every member", quiet=True)
