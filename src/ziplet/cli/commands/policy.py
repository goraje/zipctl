"""The ``policy`` command group."""

from __future__ import annotations

import argparse
from typing import Any

from ziplet.cli.commands.helpers.command import add_command, add_subcommands
from ziplet.cli.commands.helpers.output_options import add_output_options
from ziplet.cli.commands.helpers.policy_options import (
    add_policy_options,
    load_policy,
)
from ziplet.cli.commands.helpers.sources import read_text_source
from ziplet.cli.context import Context
from ziplet.cli.errors import EXIT_OK, EXIT_USAGE, CliError, UsageError
from ziplet.cli.output import count, printable, write_json
from ziplet.zipfile.extract import (
    ExtractPolicy,
)
from ziplet.zipfile.policy_config import (
    PolicyConfigError,
    policy_from_json,
    policy_to_json,
)


def cmd_policy_show(args: argparse.Namespace, ctx: Context) -> int:
    policy: ExtractPolicy = load_policy(args, ctx)
    ctx.out(policy_to_json(policy))
    return EXIT_OK


def cmd_policy_validate(args: argparse.Namespace, ctx: Context) -> int:
    if args.files.count("-") > 1:
        raise UsageError("standard input can only be given once")
    reports: list[dict[str, Any]] = []
    for source in args.files:
        issues: list[dict[str, str]] = []
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
    if args.json:
        write_json(ctx.stdout, {"ok": not invalid, "files": reports})
    else:
        for report in reports:
            name = printable(report["file"])
            if report["valid"]:
                ctx.out(f"{'OK':<8}{name}")
                continue
            ctx.out(f"{'FAILED':<8}{name}: {count(len(report['issues']), 'issue')}")
            for issue in report["issues"]:
                where = issue["path"] or "<policy>"
                ctx.out(f"  {printable(where)}: {printable(issue['message'])}")
        ctx.out()
        text = f"Checked {count(len(reports), 'policy file')}: "
        ctx.out(text + (f"{len(invalid)} failed" if invalid else "all OK"))
    return EXIT_USAGE if invalid else EXIT_OK


def register(subparsers: Any) -> None:
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
