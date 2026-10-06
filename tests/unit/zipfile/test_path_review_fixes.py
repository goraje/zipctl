from __future__ import annotations

import io
import warnings

import zipctl
from zipctl.zipfile.path import Path
from zipctl.zipfile.path.glob import Translator


def test_paths_over_one_archive_are_equal() -> None:
    buf = io.BytesIO()
    with zipctl.ZipFile(buf, "w") as zf:
        zf.writestr("a", b"")
    with zipctl.ZipFile(buf) as zf:
        assert Path(zf) == Path(zf)
        assert len({Path(zf) / "a", Path(zf) / "a"}) == 1


def test_set_operators_in_a_glob_do_not_warn() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Translator().translate("[a&&b]")
        Translator().translate("[a||b]")
