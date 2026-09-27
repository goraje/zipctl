from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

import pytest

from tests.functional.cli.support import Result, run


class CliRunner(Protocol):
    def __call__(
        self,
        *args: str,
        stdin: str | bytes | None = None,
        env: Mapping[str, str] | None = None,
        cwd: Path | None = None,
    ) -> Result: ...


@pytest.fixture
def cli() -> CliRunner:
    """Run the real CLI in a subprocess: ``cli("list", "a.zip")``."""
    return run


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """A private working directory, also used as the process cwd."""
    path = tmp_path / "work"
    path.mkdir()
    return path
