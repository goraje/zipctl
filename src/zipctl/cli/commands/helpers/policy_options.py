"""Loading the extraction policy from the environment and the command line."""

from __future__ import annotations

import argparse
from typing import Protocol

from zipctl.cli.commands.helpers.sources import read_text_source
from zipctl.cli.context import Context
from zipctl.cli.errors import UsageError
from zipctl.cli.output import printable
from zipctl.zipfile.extract import ExtractPolicy
from zipctl.zipfile.policy_config import PolicyConfigError, policy_from_json

__all__ = ["PolicyArgs", "add_policy_options", "load_policy"]

POLICY_ENV_VAR = "ZIPCTL_POLICY"


class PolicyArgs(Protocol):
    """What :func:`add_policy_options` leaves on the parsed arguments."""

    policy: str | None
    policy_json: str | None


def add_policy_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--policy",
        metavar="FILE",
        help="JSON policy file ('-' reads standard input)",
    )
    parser.add_argument(
        "--policy-json",
        metavar="TEXT",
        help="inline JSON policy, applied on top of --policy",
    )


def _parse(text: str, origin: str, base: ExtractPolicy) -> ExtractPolicy:
    try:
        return policy_from_json(text, base=base)
    except PolicyConfigError as exc:
        raise UsageError(
            f"invalid policy ({origin})",
            tuple(printable(str(issue)) for issue in exc.issues),
        ) from None


def load_policy(args: PolicyArgs, ctx: Context) -> ExtractPolicy:
    """Build the effective policy from the command-line options."""
    policy = ExtractPolicy()
    default_file = ctx.environ.get(POLICY_ENV_VAR)
    if default_file:
        if default_file == "-":
            raise UsageError(f"{POLICY_ENV_VAR} must name a file, not standard input")
        text = read_text_source(default_file, ctx, "policy file")
        policy = _parse(text, f"{POLICY_ENV_VAR}={printable(default_file)}", policy)
    if args.policy is not None:
        text = read_text_source(args.policy, ctx, "policy file")
        policy = _parse(text, f"--policy {printable(args.policy)}", policy)
    if args.policy_json is not None:
        policy = _parse(args.policy_json, "--policy-json", policy)
    return policy
