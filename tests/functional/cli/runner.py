"""In-process CLI runner, after Typer's ``CliRunner``: ``runner.invoke(app, args)``."""

from __future__ import annotations

import io
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from tests.functional.cli.support import Result, clean_env
from zipctl.cli import main

__all__ = ["CliRunner"]

App = Callable[[Sequence[str]], int]


def _text(raw: io.BytesIO) -> io.TextIOWrapper:
    """A text stream over *raw*, so commands can still reach ``.buffer``."""
    return io.TextIOWrapper(raw, encoding="utf-8", newline="\n", write_through=True)


class CliRunner:
    """Run the CLI inside this process with captured streams and environment."""

    def invoke(
        self,
        app: App,
        args: Sequence[str],
        *,
        stdin: str | bytes | None = None,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> Result:
        data = stdin if isinstance(stdin, bytes) else (stdin or "").encode()
        out, err = io.BytesIO(), io.BytesIO()
        stdout, stderr = _text(out), _text(err)
        code = 0
        before = Path.cwd()
        with (
            mock.patch.dict(os.environ, clean_env(env), clear=True),
            mock.patch.object(sys, "stdin", _text(io.BytesIO(data))),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            try:
                os.chdir(cwd or before)
                code = app(list(args))
            except SystemExit as exc:
                code = exc.code if isinstance(exc.code, int) else int(bool(exc.code))
            finally:
                os.chdir(before)
            stdout.flush()
            stderr.flush()
        return Result(
            code,
            out.getvalue().decode("utf-8"),
            err.getvalue().decode("utf-8"),
        )

    def __call__(
        self,
        *args: str,
        stdin: str | bytes | None = None,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> Result:
        """Shorthand for ``invoke(main, args)``: ``cli("list", "a.zip")``."""
        return self.invoke(main, args, stdin=stdin, env=env, cwd=cwd)
