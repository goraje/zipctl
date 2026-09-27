"""Reading a password from a file, standard input, the environment or a prompt."""

from __future__ import annotations

import getpass
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from ziplet.cli.context import Context
from ziplet.cli.errors import UsageError, os_error_text
from ziplet.cli.output import printable

ENV_VAR = "ZIPLET_PASSWORD"
OLD_ENV_VAR = "ZIPLET_OLD_PASSWORD"  # the password being replaced (rewrite)
WAYS_TO_GIVE = (
    f"use --password-file, --password-stdin or ${ENV_VAR}, or run in a terminal"
)


@dataclass(frozen=True)
class PasswordReaders:
    """Where a password reference is read from; tests can hand in their own."""

    env: Mapping[str, str]
    file: Callable[[str], bytes]
    stdin: Callable[[], bytes]


def readers_for(ctx: Context) -> PasswordReaders:
    """The readers of a real run: the environment, files, standard input."""
    return PasswordReaders(
        ctx.environ, read_password_file, lambda: read_stdin_password(ctx)
    )


def require_tty_for_prompt(ctx: Context) -> None:
    """Refuse ``--password-prompt`` when standard input is not a terminal."""
    if not ctx.stdin.isatty():
        raise UsageError("--password-prompt needs a terminal on standard input")


def password_bytes(text: str) -> bytes:
    """The bytes a typed or environment password stands for."""
    return text.encode("utf-8", "surrogateescape")


def prompt_password(label: str) -> str:
    """Prompt on the terminal, masking input where the Python version can.

    End of input answers with the empty string, like an empty answer.
    """
    try:
        if sys.version_info >= (3, 14):
            return getpass.getpass(label, echo_char="*")  # pyright: ignore[reportUnreachable]  # branch depends on the Python version
        return getpass.getpass(label)
    except EOFError:
        return ""


def _strip_newline(line: bytes) -> bytes:
    if line.endswith(b"\r\n"):
        return line[:-2]
    if line.endswith(b"\n"):
        return line[:-1]
    return line


def read_password_file(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            line = handle.readline()
    except OSError as exc:
        raise UsageError(
            f"cannot read password file {printable(path)}: {os_error_text(exc)}",
        ) from None
    password = _strip_newline(line)
    if not password:
        raise UsageError(f"password file {printable(path)} is empty")
    return password


def read_stdin_password(ctx: Context, *, old: bool = False) -> bytes:
    option = "--old-password-stdin" if old else "--password-stdin"
    if ctx.stdin.isatty():
        raise UsageError(
            f"{option} expects the password piped on standard input, not typed "
            "at a terminal (it would be echoed)"
            + ("" if old else "; use --password-prompt to type one"),
        )
    ctx.claim_stdin("the input password" if old else "the password")
    password = _strip_newline(ctx.read_stdin(line=True))
    if not password:
        raise UsageError("no password on standard input")
    return password


def static_passwords(
    ctx: Context,
    *,
    file: str | None,
    stdin: bool,
    old: bool = False,
    use_env: bool = True,
) -> list[bytes]:
    """The passwords given up front: file, standard input, else the environment.

    ``--password-prompt`` (``use_env=False``) leaves the environment out.
    """
    passwords: list[bytes] = []
    if file is not None:
        passwords.append(read_password_file(file))
    if stdin:
        passwords.append(read_stdin_password(ctx, old=old))
    if not passwords and use_env:
        value = ctx.environ.get(OLD_ENV_VAR if old else ENV_VAR)
        if value:
            passwords.append(password_bytes(value))
    return list(dict.fromkeys(passwords))


def prompt_new_password(
    label: str,
    ctx: Context,
    *,
    hint: str | None = None,
    prompt: Callable[[str], str] = prompt_password,
) -> bytes:
    """Ask twice for a password that is about to protect something.

    *label* reads like ``Password for secrets/**``; it is shown as typed for the
    first prompt and, lower-cased at its first letter, in ``Confirm ...``.
    """
    if not ctx.stdin.isatty():
        raise UsageError(
            hint or f"no password given ({WAYS_TO_GIVE})",
        )
    first = prompt(f"{label}: ")
    if not first:
        raise UsageError("no password entered")
    again = prompt(f"Confirm {label[:1].lower()}{label[1:]}: ")
    if first != again:
        raise UsageError("the passwords do not match")
    return password_bytes(first)
