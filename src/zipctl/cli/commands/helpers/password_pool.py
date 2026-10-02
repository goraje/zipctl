"""Matching known and prompted passwords to encrypted members."""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum

from zipctl.cli.commands.helpers.password_sources import (
    WAYS_TO_GIVE,
    password_bytes,
    prompt_password,
    require_tty_for_prompt,
    static_passwords,
)
from zipctl.cli.context import Context
from zipctl.cli.output import printable
from zipctl.zipfile.file import ZipFile
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.password import PasswordStatus

MAX_PROMPT_ATTEMPTS = 3


class PasswordProblem(Enum):
    """Why a member could not be given a password."""

    MISSING = "no_password"
    WRONG = "wrong_password"
    CORRUPT = "corrupt"

    @property
    def text(self) -> str:
        """Human wording for the problem."""
        if self is PasswordProblem.WRONG:
            return "wrong password"
        if self is PasswordProblem.CORRUPT:
            return "corrupt data, or the password is wrong"
        return f"password required ({WAYS_TO_GIVE})"


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
        prompt: Callable[[str], str] = prompt_password,
    ) -> None:
        self._known: list[bytes] = list(known)
        self._ctx: Context = ctx
        self._can_prompt: bool = can_prompt
        self._prompt: Callable[[str], str] = prompt

    @staticmethod
    def _status(
        zf: ZipFile, info: ZipInfo, password: bytes, *, full: bool = False
    ) -> PasswordStatus:
        return zf.check_password(password, members=[info], full=full).members[0].status

    def resolve(self, zf: ZipFile, info: ZipInfo) -> bytes | PasswordProblem:
        """Find the password for encrypted *info*, or say why there is none."""
        problem = PasswordProblem.MISSING
        # The verifier is cheap and rejects most wrong passwords.  Reading the
        # member is what authenticates it, so only a tie between several
        # verifier matches (a collision) is settled by a full check here.
        likely = [
            password
            for password in self._known
            if self._status(zf, info, password) is PasswordStatus.ACCEPTED
        ]
        if self._known:
            problem = PasswordProblem.WRONG
        if len(likely) == 1:
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
            text = self._prompt(label)
            if not text:
                # An empty answer (or end of input) means "stop asking".
                self._can_prompt = False
                return problem
            if problem is PasswordProblem.MISSING:
                problem = PasswordProblem.WRONG
            password = password_bytes(text)
            if self._status(zf, info, password) is PasswordStatus.ACCEPTED:
                self._known.insert(0, password)  # tried first on the next member
                return password
            if attempt + 1 < MAX_PROMPT_ATTEMPTS:
                self._ctx.err("zipctl: incorrect password, try again")
        return problem


def build_password_pool(
    ctx: Context,
    *,
    file: str | None,
    stdin: bool,
    prompt: bool,
    old: bool = False,
) -> PasswordPool:
    """Collect password sources from a file, standard input and the environment.

    *prompt* is ``--password-prompt``: insist on asking at a terminal.
    """
    interactive = ctx.stdin.isatty()
    if prompt:
        require_tty_for_prompt(ctx)
    known = static_passwords(ctx, file=file, stdin=stdin, old=old, use_env=not prompt)
    return PasswordPool(known, ctx, can_prompt=interactive and not stdin)
