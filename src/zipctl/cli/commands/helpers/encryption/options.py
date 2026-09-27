"""The encryption options of ``create`` and ``rewrite``, and the plan they build."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from zipctl.cli.commands.helpers.encryption.plan import EncryptionPlan, Rule
from zipctl.cli.commands.helpers.encryption.spec import plan_from_spec
from zipctl.cli.commands.helpers.passwords.options import (
    PasswordArgs,
    PasswordOptions,
    given_password,
)
from zipctl.cli.commands.helpers.passwords.sources import (
    readers_for,
    require_tty_for_prompt,
)
from zipctl.cli.commands.helpers.sources import read_text_source
from zipctl.cli.context import Context
from zipctl.cli.errors import UsageError
from zipctl.cli.methods import (
    ENCRYPTION_METHODS,
    METHOD_CHOICES,
    NO_ENCRYPTION,
    EncryptionMethod,
)
from zipctl.cli.output import did_you_mean, printable
from zipctl.cryptography import WZ_AES_DEFAULT_VERSION


class EncryptionArgs(PasswordArgs, Protocol):
    """What :func:`add_encryption_options` leaves on the parsed arguments."""

    encryption: str | None
    protect: list[str]
    encryption_spec: str | None
    wz_aes_version: int | None


@dataclass(frozen=True)
class EncryptionOptions:
    """The options of :func:`add_encryption_options`, with the password options."""

    encryption: str | None
    protect: list[str]
    spec: str | None
    wz_aes_version: int | None
    passwords: PasswordOptions

    @classmethod
    def from_args(cls, args: EncryptionArgs) -> EncryptionOptions:
        return cls(
            args.encryption,
            args.protect,
            args.encryption_spec,
            args.wz_aes_version,
            PasswordOptions.from_args(args),
        )


def plan_from_options(options: EncryptionOptions, ctx: Context) -> EncryptionPlan:
    """The plan for ``--encryption`` and ``--protect`` (passwords come later)."""
    rules: list[Rule] = []
    for text in options.protect:
        pattern, name = _split_protect(text)
        if not pattern:
            raise UsageError("--protect needs a pattern")
        method = ENCRYPTION_METHODS[name]
        typed = method.is_encrypted
        rules.append(
            Rule(
                pattern,
                method,
                prompt=f"Password for {pattern}" if typed else None,
                hint=(
                    f"the password for {printable(pattern)} can only be typed at a "
                    "terminal; use --encryption-spec to script it"
                    if typed
                    else None
                ),
            )
        )
    default = options.encryption
    passwords = options.passwords
    sources = passwords.file is not None or passwords.stdin
    if default in (None, "none"):
        if sources or passwords.prompt:
            raise UsageError(
                "a password option was given but --encryption names nothing to "
                "protect with it (--protect rules ask for their own passwords)",
            )
        if default == "none":
            rules.append(Rule(None, NO_ENCRYPTION))
    else:
        if passwords.prompt:
            require_tty_for_prompt(ctx)
        password = given_password(passwords, ctx)
        rules.append(
            Rule(
                None,
                ENCRYPTION_METHODS[default],
                password=password,
                prompt=None if password else "Password",
            )
        )
    return EncryptionPlan(rules)


def _split_protect(text: str) -> tuple[str, str]:
    """Split ``GLOB[=METHOD]``; the method is only taken if it is a known one.

    A suffix that is not a method but nearly is (``=aes265``) is a typo, not
    part of the glob.
    """
    pattern, _, method = text.rpartition("=")
    if pattern and method in ENCRYPTION_METHODS:
        return pattern, method
    guess = did_you_mean(method, list(ENCRYPTION_METHODS)) if pattern else ""
    if guess:
        raise UsageError(
            f"--protect {printable(text)!r}: unknown method {printable(method)!r}"
            f"{guess} (choose from {METHOD_CHOICES})",
        )
    return text, "aes256"


def build_plan(options: EncryptionOptions, ctx: Context) -> EncryptionPlan:
    """The plan for ``--encryption``/``--protect`` or for ``--encryption-spec``."""
    if options.spec is None:
        plan = plan_from_options(options, ctx)
    else:
        if options.encryption is not None or options.protect:
            raise UsageError(
                "--encryption-spec cannot be combined with --encryption or --protect; "
                "put those rules in the spec",
            )
        passwords = options.passwords
        if passwords.file is not None or passwords.stdin or passwords.prompt:
            raise UsageError(
                "password options do not apply with --encryption-spec; the spec says "
                "where each password comes from",
            )
        text = read_text_source(options.spec, ctx, "encryption spec")
        plan = plan_from_spec(text, options.spec, readers_for(ctx))
    require_aes_for_version(options.wz_aes_version, plan.methods)
    return plan


def require_aes_for_version(
    version: int | None, methods: Iterable[EncryptionMethod]
) -> None:
    """Refuse ``--wz-aes-version`` when none of *methods* is an AES one."""
    if version is not None and not any(method.is_aes for method in methods):
        raise UsageError("--wz-aes-version only applies to AES encryption")


def add_wz_aes_version(parser: argparse.ArgumentParser) -> None:
    """Add ``--wz-aes-version`` to *parser*."""
    parser.add_argument(
        "--wz-aes-version",
        type=int,
        choices=(1, 2),
        metavar="VERSION",
        help=f"WinZip AES version to write: 1 or 2. Default: {WZ_AES_DEFAULT_VERSION}",
    )


def add_encryption_options(parser: argparse.ArgumentParser) -> None:
    """Add the encryption options: method, per-member rules, spec file, AES version."""
    parser.add_argument(
        "--encryption",
        metavar="METHOD",
        choices=list(ENCRYPTION_METHODS),
        help=f"Encryption method: {METHOD_CHOICES}",
    )
    parser.add_argument(
        "--protect",
        action="append",
        default=[],
        metavar="GLOB[=METHOD]",
        help="Encrypt members matching GLOB, or leave them plain with GLOB=none. "
        "Repeatable. Default: aes256",
    )
    parser.add_argument(
        "--encryption-spec",
        metavar="FILE",
        help="JSON file with the rules and password references ('-' is standard input)",
    )
    add_wz_aes_version(parser)
