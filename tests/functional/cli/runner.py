"""In-process CLI runner, after Typer's ``CliRunner``: ``runner.invoke(args)``."""

from __future__ import annotations

import io
import os
from collections.abc import Mapping, Sequence
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from typing_extensions import override

from tests.functional.cli.support import Result, clean_env
from zipctl.cli import main
from zipctl.cli.context import Context

__all__ = ["CliRunner"]


def _text(raw: io.BytesIO) -> io.TextIOWrapper:
    """A text stream over *raw*, so commands can still reach ``.buffer``."""
    return io.TextIOWrapper(raw, encoding="utf-8", newline="\n", write_through=True)


class _Terminal(io.TextIOWrapper):
    """Standard input that says it is a terminal."""

    @override
    def isatty(self) -> bool:
        return True


class _Typist:
    """Answers password prompts with *replies*, as getpass does without a tty.

    The prompt goes to standard error; running out of replies is end of input.
    """

    def __init__(self, replies: Sequence[str], stderr: io.TextIOWrapper) -> None:
        self.replies: list[str] = list(replies)
        self.stderr: io.TextIOWrapper = stderr
        self.asked: int = 0

    def __call__(self, label: str) -> str:
        self.asked += 1
        self.stderr.write(label)
        reply = self.replies.pop(0) if self.replies else ""
        self.stderr.write("\n")
        return reply


class CliRunner:
    """Run the CLI inside this process with its own streams and environment."""

    def invoke(
        self,
        args: Sequence[str],
        *,
        stdin: str | bytes | None = None,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
        replies: Sequence[str] | None = None,
    ) -> tuple[Result, int]:
        """Run ``zipctl ARGS``; with *replies*, standard input is a terminal.

        Returns the result and the number of password prompts answered.
        """
        data = stdin if isinstance(stdin, bytes) else (stdin or "").encode()
        out, err = io.BytesIO(), io.BytesIO()
        stdout, stderr = _text(out), _text(err)
        raw_in = io.BytesIO(data)
        tty = replies is not None
        stdin_stream = (
            _Terminal(raw_in, encoding="utf-8", newline="\n") if tty else _text(raw_in)
        )
        typist = _Typist(replies or (), stderr)
        ctx = Context(stdin_stream, stdout, stderr, clean_env(env), prompt=typist)
        code = 0
        before = Path.cwd()
        # argparse writes usage, errors and --help to the sys streams itself
        try:
            os.chdir(cwd or before)
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(list(args), ctx)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else int(bool(exc.code))
        finally:
            os.chdir(before)
        stdout.flush()
        stderr.flush()
        result = Result(
            code,
            out.getvalue().decode("utf-8"),
            err.getvalue().decode("utf-8"),
        )
        return result, typist.asked

    def __call__(
        self,
        *args: str,
        stdin: str | bytes | None = None,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> Result:
        """Shorthand for ``invoke(args)[0]``: ``cli("list", "a.zip")``."""
        return self.invoke(args, stdin=stdin, env=env, cwd=cwd)[0]

    def terminal(
        self,
        *args: str,
        replies: Sequence[str] = (),
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> tuple[Result, int]:
        """Run at a scripted terminal, typing *replies* at the password prompts."""
        return self.invoke(args, env=env, cwd=cwd, replies=replies)
