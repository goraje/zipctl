"""Exercise native filesystem behavior; opt-in mounts are never formatted here."""

import errno
import io
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from tests.unit.zipfile.archive_factory import archive_bytes
from zipctl import ExtractionError, ExtractPolicy, OverwritePolicy, ZipFile
from zipctl.zipfile.secure_fs import open_secure_parent


def test_case_insensitive_collision_preserves_original(tmp_path: Path) -> None:
    existing = tmp_path / "FILE.TXT"
    existing.write_bytes(b"original")
    if not (tmp_path / "file.txt").exists():
        pytest.skip("filesystem is case-sensitive")
    with ZipFile(io.BytesIO(archive_bytes())) as archive:
        with pytest.raises(ExtractionError):
            archive.extractall(tmp_path, policy=ExtractPolicy())
    assert existing.read_bytes() == b"original"
    with ZipFile(io.BytesIO(archive_bytes())) as archive:
        result = archive.extractall(
            tmp_path, policy=ExtractPolicy(overwrite_policy=OverwritePolicy.RENAME)
        )
    assert result.failed_count == 0
    assert (tmp_path / "file.1.txt").read_bytes() == b"payload"
    assert existing.read_bytes() == b"original"


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows junctions")
@pytest.mark.parametrize("outside", [False, True])
def test_junction_parent_is_refused(tmp_path: Path, outside: bool) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = (tmp_path if outside else root) / "target"
    target.mkdir()
    junction = root / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert created.returncode == 0, created.stdout + created.stderr
    try:
        with pytest.raises(ValueError, match="unsafe extraction path"):
            open_secure_parent(str(junction), str(root))
        assert list(target.iterdir()) == []
    finally:
        junction.rmdir()


@pytest.mark.deployment
def test_real_filesystem_without_hardlinks() -> None:
    mount = os.environ.get("ZIPCTL_NO_HARDLINK_ROOT")
    if not mount:
        pytest.skip("set ZIPCTL_NO_HARDLINK_ROOT to a writable no-hard-link mount")
    assert Path(mount).is_dir(), "configured mount does not exist"
    with tempfile.TemporaryDirectory(prefix="zipctl-", dir=mount) as directory:
        root = Path(directory)
        original = root / "original"
        original.write_bytes(b"original")
        with pytest.raises(OSError) as failure:  # noqa: PT011
            os.link(original, root / "probe")
        assert failure.value.errno in (errno.EPERM, errno.ENOSYS, errno.EOPNOTSUPP)
        destination = root / "output"
        destination.mkdir()
        with ZipFile(io.BytesIO(archive_bytes())) as archive:
            with pytest.raises(ExtractionError):
                archive.extractall(destination, policy=ExtractPolicy())
        assert list(destination.iterdir()) == []
        assert original.read_bytes() == b"original"
        with ZipFile(io.BytesIO(archive_bytes())) as archive:
            result = archive.extractall(
                destination,
                policy=ExtractPolicy(overwrite_policy=OverwritePolicy.REPLACE),
            )
        assert result.failed_count == 0
        assert (destination / "file.txt").read_bytes() == b"payload"
