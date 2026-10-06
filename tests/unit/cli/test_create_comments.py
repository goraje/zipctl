"""Validate comment encoding directly, without OS argument normalization."""

import pytest

from zipctl.cli import main


@pytest.mark.parametrize(
    ("comment", "message"),
    [("a\udcffb", "not valid UTF-8"), ("x" * 70000, "too long")],
    ids=["surrogate", "oversized"],
)
def test_invalid_comment_is_usage_error(
    capsys: pytest.CaptureFixture[str], comment: str, message: str
) -> None:
    assert main(["create", "unused.zip", "source", "--comment", comment]) == 2
    assert message in capsys.readouterr().err
