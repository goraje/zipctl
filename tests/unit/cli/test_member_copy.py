"""A member copy, driven through its interface rather than the command line."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from typing_extensions import override

import zipctl
from tests.unit.cli.conftest import new_context
from zipctl import ZipFile
from zipctl.cli.commands.helpers.copy import Intent, open_copy
from zipctl.cli.commands.helpers.encryption_plan import Protection
from zipctl.cli.commands.helpers.passwords import PasswordPool
from zipctl.cli.methods import ENCRYPTION_METHODS
from zipctl.zipfile.info import ZipInfo

OLD = b"old secret"
NEW = b"new secret"


@dataclass
class _Args:
    """What ``add_copy_options`` leaves on the parsed arguments."""

    input: str
    output: str
    force: bool = False
    no_verify: bool = False


def _args(tmp_path: Path) -> _Args:
    source = tmp_path / "in.zip"
    with ZipFile(source, "w", encryption=zipctl.WZ_AES) as zf:
        zf.writestr("locked.txt", b"locked", password=OLD)
        zf.writestr("plain.txt", b"plain", encryption=None)
    return _Args(str(source), str(tmp_path / "out.zip"))


def _schemes(path: str) -> dict[str, bool]:
    with ZipFile(path) as zf:
        return {info.filename: info.is_encrypted for info in zf.infolist()}


def test_a_kept_member_needs_no_password(tmp_path: Path) -> None:
    args = _args(tmp_path)
    ctx = new_context()
    with open_copy(args, ctx) as copy:
        assert copy.run(lambda _info: Intent.KEEP, verb="Copied") == 0
    assert _schemes(args.output) == {"locked.txt": True, "plain.txt": False}


def test_new_protection_is_asked_for_only_after_every_member_is_unlocked(
    tmp_path: Path,
) -> None:
    args = _args(tmp_path)
    ctx = new_context()
    events: list[str] = []

    class Pool(PasswordPool):
        @override
        def resolve(self, zf: ZipFile, info: ZipInfo) -> bytes:
            events.append(f"unlock {info.filename}")
            return OLD

    def protect(info: ZipInfo) -> Protection:
        events.append(f"protect {info.filename}")
        return Protection(ENCRYPTION_METHODS["aes256"], NEW)

    with open_copy(args, ctx) as copy:
        copy.run(
            lambda _info: Intent.NEW,
            verb="Rewrote",
            pool=Pool([], ctx, can_prompt=False),
            protect=protect,
        )
    assert events == ["unlock locked.txt", "protect locked.txt", "protect plain.txt"]
    with ZipFile(args.output) as zf:
        assert zf.read("locked.txt", pwd=NEW) == b"locked"
