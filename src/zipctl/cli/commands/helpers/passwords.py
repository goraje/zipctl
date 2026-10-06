"""Where passwords come from, the options naming them, and matching them to members."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from zipctl.cli.context import Context
from zipctl.cli.errors import UsageError, os_error_text
from zipctl.cli.output import printable
from zipctl.zipfile.file import ZipFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.password import PasswordStatus

# --- password sources ------------------------------------------------------

ENV_VAR = "ZIPCTL_PASSWORD"
OLD_ENV_VAR = "ZIPCTL_OLD_PASSWORD"  # the password being replaced (rewrite)
WAYS_TO_GIVE = (
    f"use --password-file, --password-stdin or ${ENV_VAR}, or run in a terminal"
)
OLD_WAYS_TO_GIVE = (
    "use --old-password-file, --old-password-stdin or "
    f"${OLD_ENV_VAR}, or run in a terminal"
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
    password = _strip_newline(line).removeprefix(b"\xef\xbb\xbf")  # a UTF-8 BOM
    if not password:
        raise UsageError(f"password file {printable(path)} is empty")
    if _looks_like_utf16(password):
        raise UsageError(
            f"password file {printable(path)} looks like UTF-16 text; save it as UTF-8"
        )
    return password


def _looks_like_utf16(data: bytes) -> bool:
    """Whether *data* starts as UTF-16 text: a byte order mark, then ASCII."""
    if data[:2] == b"\xff\xfe":  # little-endian
        return data[3:4] == b"\0"
    return data[:2] == b"\xfe\xff" and data[2:3] == b"\0"


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


def prompt_new_password(
    label: str,
    ctx: Context,
    *,
    hint: str | None = None,
) -> bytes:
    """Ask twice for a password that is about to protect something.

    *label* reads like ``Password for secrets/**``; it is shown as typed for the
    first prompt and, lower-cased at its first letter, in ``Confirm ...``.
    """
    if not ctx.stdin.isatty():
        raise UsageError(
            hint or f"no password given ({WAYS_TO_GIVE})",
        )
    first = ctx.ask(f"{label}: ")
    if not first:
        raise UsageError("no password entered")
    again = ctx.ask(f"Confirm {label[:1].lower()}{label[1:]}: ")
    if first != again:
        raise UsageError("the passwords do not match")
    return password_bytes(first)


# --- password options ------------------------------------------------------


class PasswordArgs(Protocol):
    """What :func:`add_password_options` leaves on the parsed arguments."""

    password_file: str | None
    password_stdin: bool
    password_prompt: bool


class OldPasswordArgs(Protocol):
    """What :func:`add_old_password_options` leaves on the parsed arguments."""

    old_password_file: str | None
    old_password_stdin: bool


@dataclass(frozen=True)
class PasswordFamily:
    """One set of password sources.

    The ``--password-*`` options with ``$ZIPCTL_PASSWORD``, or the
    ``--old-password-*`` ones with ``$ZIPCTL_OLD_PASSWORD`` (a rewrite's input).
    """

    file: str | None = None
    stdin: bool = False
    prompt: bool = False  # --password-prompt: insist on asking at a terminal
    old: bool = False

    @classmethod
    def from_args(cls, args: PasswordArgs) -> PasswordFamily:
        return cls(args.password_file, args.password_stdin, args.password_prompt)

    @classmethod
    def old_from_args(cls, args: OldPasswordArgs) -> PasswordFamily:
        return cls(args.old_password_file, args.old_password_stdin, old=True)

    @property
    def ways(self) -> str:
        """How to give a password, for a message about a missing one."""
        return OLD_WAYS_TO_GIVE if self.old else WAYS_TO_GIVE

    def given(self, ctx: Context) -> list[bytes]:
        """The passwords given up front: file, standard input, else the environment.

        ``--password-prompt`` leaves the environment out.
        """
        passwords: list[bytes] = []
        if self.file is not None:
            passwords.append(read_password_file(self.file))
        if self.stdin:
            passwords.append(read_stdin_password(ctx, old=self.old))
        if not passwords and not self.prompt:
            value = ctx.environ.get(OLD_ENV_VAR if self.old else ENV_VAR)
            if value:
                passwords.append(password_bytes(value))
        return list(dict.fromkeys(passwords))

    def given_one(self, ctx: Context) -> bytes | None:
        """The one password from a source (file, stdin, environment), if any."""
        known = self.given(ctx)
        _require_one(known, "this command uses")
        return known[0] if known else None

    def ask_one(self, ctx: Context) -> bytes:
        """The one password a command asks about: from a source, else prompted for."""
        known = self.given(ctx)
        _require_one(known, "this command tests")
        if known:
            return known[0]
        if not ctx.stdin.isatty():
            if self.prompt:
                require_tty_for_prompt(ctx)
            raise UsageError(f"no password given ({self.ways})")
        text = ctx.ask("Password: ")
        if not text:
            raise UsageError("no password entered")
        return password_bytes(text)

    def pool(self, ctx: Context) -> PasswordPool:
        """A pool of these passwords, asking at a terminal for any still missing."""
        interactive = ctx.stdin.isatty()
        if self.prompt:
            require_tty_for_prompt(ctx)
        return PasswordPool(
            self.given(ctx),
            ctx,
            can_prompt=interactive and not self.stdin,
            ways=self.ways,
        )


def _require_one(known: list[bytes], what: str) -> None:
    if len(known) > 1:
        raise UsageError(
            f"{what} one password; give --password-file or --password-stdin "
            "with a single value, not different ones",
        )


def add_password_options(parser: argparse.ArgumentParser) -> None:
    """Add ``--password-prompt``, ``--password-stdin`` and ``--password-file``."""
    parser.add_argument(
        "--password-prompt",
        action="store_true",
        help="ask for passwords at the terminal",
    )
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="read one password from the first line of standard input",
    )
    parser.add_argument(
        "--password-file",
        metavar="FILE",
        help="read one password from the first line of FILE",
    )


def add_old_password_options(parser: argparse.ArgumentParser) -> None:
    """Options for the passwords that unlock the input of a rewrite."""
    parser.add_argument(
        "--old-password-stdin",
        action="store_true",
        help="read the input password from the first line of standard input",
    )
    parser.add_argument(
        "--old-password-file",
        metavar="FILE",
        help="read the input password from the first line of FILE",
    )


# --- password pool ---------------------------------------------------------

MAX_PROMPT_ATTEMPTS = 3


class PasswordProblem(Enum):
    """Why a member could not be given a password."""

    MISSING = "no_password"
    WRONG = "wrong_password"
    CORRUPT = "corrupt"

    def explain(self, ways: str) -> str:
        """Human wording for the problem, with *ways* to give a missing password."""
        if self is PasswordProblem.WRONG:
            return "wrong password"
        if self is PasswordProblem.CORRUPT:
            return "corrupt data, or the password is wrong"
        return f"password required ({ways})"


class PasswordPool:
    """Passwords known so far, matched to members one at a time.

    An archive with one password asks for it once; an archive whose members use
    different passwords asks once per distinct password, because every accepted
    password is remembered and tried on the next member first.  Answering with
    nothing (or end of input) stops all further prompting for the run.
    """

    def __init__(
        self,
        known: list[bytes],
        ctx: Context,
        *,
        can_prompt: bool,
        ways: str = WAYS_TO_GIVE,
    ) -> None:
        self.ways: str = ways  # how to give a password, for a missing one
        self._known: list[bytes] = list(known)
        self._ctx: Context = ctx
        self._can_prompt: bool = can_prompt

    def explain(self, problem: PasswordProblem) -> str:
        """Human wording for *problem*, naming this pool's ways to give a password."""
        return problem.explain(self.ways)

    @staticmethod
    def _status(
        zf: ZipFile, info: ZipInfo, password: bytes, *, full: bool = False
    ) -> PasswordStatus:
        return zf.check_password(password, members=[info], full=full).members[0].status

    def resolve(self, zf: ZipFile, info: ZipInfo) -> bytes | PasswordProblem:
        """Find the password for encrypted *info*, or say why there is none."""
        problem = PasswordProblem.MISSING
        # The verifier is cheap and rejects most wrong passwords.  Reading the
        # member is what authenticates it, so a tie between several verifier
        # matches (a collision) is settled by a full check here.  So is any
        # ZipCrypto match: its one-byte verifier passes about one wrong
        # password in 256, and a member copied as it is is never read again.
        statuses = {
            password: self._status(zf, info, password) for password in self._known
        }
        likely = [
            password
            for password, status in statuses.items()
            if status is PasswordStatus.ACCEPTED
        ]
        if self._known:
            problem = PasswordProblem.WRONG
        if PasswordStatus.CORRUPT in statuses.values():
            # Its headers are broken (an overlapping entry, say): no password helps.
            return PasswordProblem.CORRUPT
        if len(likely) == 1 and info.is_aes:
            return likely[0]
        for password in likely:
            status = self._status(zf, info, password, full=True)
            if status is PasswordStatus.ACCEPTED:
                return password
            if status is PasswordStatus.CORRUPT:
                problem = PasswordProblem.CORRUPT
        if not self._can_prompt:
            return problem
        return self._prompt_for(zf, info, problem)

    def _prompt_for(
        self, zf: ZipFile, info: ZipInfo, problem: PasswordProblem
    ) -> bytes | PasswordProblem:
        label = f"Password for {printable(info.filename)}: "
        for attempt in range(MAX_PROMPT_ATTEMPTS):
            text = self._ctx.ask(label)
            if not text:
                # An empty answer (or end of input) means "stop asking".
                self._can_prompt = False
                return problem
            if problem is PasswordProblem.MISSING:
                problem = PasswordProblem.WRONG
            password = password_bytes(text)
            status = self._status(zf, info, password)
            if status is PasswordStatus.CORRUPT:  # as in resolve(): no password helps
                return PasswordProblem.CORRUPT
            if status is PasswordStatus.ACCEPTED and not info.is_aes:
                status = self._status(zf, info, password, full=True)
                if status is PasswordStatus.CORRUPT:
                    # a verifier collision or damaged data: ask again, as in resolve()
                    problem = PasswordProblem.CORRUPT
            if status is PasswordStatus.ACCEPTED:
                self._known.insert(0, password)  # tried first on the next member
                return password
            if attempt + 1 < MAX_PROMPT_ATTEMPTS:
                self._ctx.output.note("incorrect password, try again")
        return problem
