from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

import pytest

from tests.functional.cli.runner import CliRunner
from tests.functional.cli.support import Result, run

__all__ = ["CliRunner", "SubprocessRunner"]


class SubprocessRunner(Protocol):
    def __call__(
        self,
        *args: str,
        stdin: str | bytes | None = None,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> Result: ...


@pytest.fixture
def cli() -> CliRunner:
    """Run the CLI in this process: ``cli("list", "a.zip")``."""
    return CliRunner()


@pytest.fixture
def cli_subprocess() -> SubprocessRunner:
    """Run ``python -m zipctl`` as a child process, for what only a process shows."""
    return run


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """A private working directory, also used as the process cwd."""
    path = tmp_path / "work"
    path.mkdir()
    return path
