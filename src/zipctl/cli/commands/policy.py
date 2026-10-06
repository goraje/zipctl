"""The ``policy`` command group."""

from __future__ import annotations

from typing import Protocol

from zipctl.cli.commands.helpers.command import Subparsers, add_command, add_subcommands
from zipctl.cli.commands.helpers.output_options import add_output_options
from zipctl.cli.commands.helpers.policy_options import (
    PolicyArgs,
    add_policy_options,
    load_policy,
)
from zipctl.cli.commands.helpers.sources import read_text_source
from zipctl.cli.context import Context
from zipctl.cli.errors import EXIT_OK, EXIT_USAGE, CliError, UsageError
from zipctl.cli.output import count, printable
from zipctl.cli.reports import PolicyFile, PolicyIssue, PolicyValidateReport
from zipctl.zipfile.policy import (
    ExtractPolicy,
)
from zipctl.zipfile.policy_config import (
    PolicyConfigError,
    policy_from_json,
    policy_to_json,
)


class ValidateArgs(Protocol):
    files: list[str]


def cmd_policy_show(args: PolicyArgs, ctx: Context) -> int:
    policy: ExtractPolicy = load_policy(args, ctx)
    ctx.output.line(policy_to_json(policy))
    return EXIT_OK


def cmd_policy_validate(args: ValidateArgs, ctx: Context) -> int:
    if args.files.count("-") > 1:
        raise UsageError("standard input can only be given once")
    reports: list[PolicyFile] = []
    for source in args.files:
        issues: list[PolicyIssue] = []
        try:
            policy_from_json(read_text_source(source, ctx, "policy file"))
        except PolicyConfigError as exc:
            issues = [
                {"path": issue.path, "message": issue.message} for issue in exc.issues
            ]
        except CliError as exc:  # unreadable file: report it and check the others
            issues = [{"path": "", "message": exc.message}]
        reports.append({"file": source, "valid": not issues, "issues": issues})

    invalid = [report for report in reports if not report["valid"]]
    output = ctx.output
    if output.json:
        document: PolicyValidateReport = {"ok": not invalid, "files": reports}
        output.document(document)
        return EXIT_USAGE if invalid else EXIT_OK
    for report in reports:
        name = printable(report["file"])
        if report["valid"]:
            output.line(f"{'OK':<8}{name}")
            continue
        output.problem(f"{'FAILED':<8}{name}: {count(len(report['issues']), 'issue')}")
        for issue in report["issues"]:
            where = issue["path"] or "<policy>"
            output.problem(f"  {printable(where)}: {printable(issue['message'])}")
    text = f"Checked {count(len(reports), 'policy file')}: "
    output.summary(text + (f"{len(invalid)} failed" if invalid else "all OK"))
    return EXIT_USAGE if invalid else EXIT_OK


def register(subparsers: Subparsers) -> None:
    parser = add_command(
        subparsers, "policy", None, "show or validate extraction policies"
    )
    actions = add_subcommands(parser, "policy_command")
    show = add_command(
        actions, "show", cmd_policy_show, "print the effective policy as JSON"
    )
    add_policy_options(show)
    validate = add_command(
        actions,
        "validate",
        cmd_policy_validate,
        "check policy files without needing an archive",
    )
    validate.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="policy file ('-' reads standard input)",
    )
    add_output_options(validate)
