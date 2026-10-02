"""``zipctl create --symlinks {follow,store,skip}``."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.reports import ListReport, load_json
from tests.functional.cli.support import PASSWORD
from zipctl import ZipFile

pytestmark = pytest.mark.skipif(os.name != "posix", reason="needs symbolic links")


@pytest.fixture
def tree(workdir: Path) -> Path:
    root = workdir / "t"
    (root / "real").mkdir(parents=True)
    (root / "real" / "f.txt").write_bytes(b"content")
    (root / "file.txt").write_bytes(b"plain")
    (root / "flink").symlink_to("file.txt")
    (root / "dlink").symlink_to("real", target_is_directory=True)
    (root / "broken").symlink_to("../nowhere")
    return root


def make(cli: CliRunner, workdir: Path, *args: str) -> tuple[int, str, str]:
    result = cli("create", "out.zip", "t", *args, cwd=workdir)
    return result.returncode, result.stdout, result.stderr


def links(workdir: Path) -> dict[str, str]:
    with ZipFile(workdir / "out.zip") as zf:
        return {
            info.filename: zf.read(info).decode()
            for info in zf.infolist()
            if stat.S_ISLNK(info.external_attr >> 16)
        }


def files(workdir: Path) -> list[str]:
    with ZipFile(workdir / "out.zip") as zf:
        return sorted(n for n in zf.namelist() if not n.endswith("/"))


@pytest.mark.usefixtures("tree")
def test_follow_is_the_default_and_stores_no_link(
    cli: CliRunner, workdir: Path
) -> None:
    code, _, err = make(cli, workdir)
    assert code == 0, err
    assert links(workdir) == {}
    assert files(workdir) == ["t/file.txt", "t/flink", "t/real/f.txt"]
    assert "skipping t/dlink: symbolic link to a directory" in err
    assert "skipping t/broken: broken symbolic link" in err


@pytest.mark.usefixtures("tree")
def test_store_keeps_every_link_as_a_link(cli: CliRunner, workdir: Path) -> None:
    code, out, err = make(cli, workdir, "--symlinks", "store")
    assert code == 0, err
    assert links(workdir) == {
        "t/flink": "file.txt",
        "t/dlink": "real",
        "t/broken": "../nowhere",
    }
    assert files(workdir) == [
        "t/broken",
        "t/dlink",
        "t/file.txt",
        "t/flink",
        "t/real/f.txt",
    ]
    assert "skipping" not in err
    assert "5 files" in out
    with ZipFile(workdir / "out.zip") as zf:
        assert zf.testzip() is None
        assert zf.getinfo("t/dlink").compress_type == 0


@pytest.mark.usefixtures("tree")
def test_skip_leaves_every_link_out_with_a_warning(
    cli: CliRunner, workdir: Path
) -> None:
    code, _, err = make(cli, workdir, "--symlinks", "skip")
    assert code == 0, err
    assert files(workdir) == ["t/file.txt", "t/real/f.txt"]
    for name in ("flink", "dlink", "broken"):
        assert f"skipping t/{name}: symbolic link" in err


@pytest.mark.usefixtures("tree")
def test_a_link_named_on_the_command_line_follows_the_mode(
    cli: CliRunner, workdir: Path
) -> None:
    result = cli("create", "a.zip", "t/flink", "--symlinks", "store", cwd=workdir)
    assert result.returncode == 0, result
    with ZipFile(workdir / "a.zip") as zf:
        info = zf.getinfo("t/flink")
        assert stat.S_ISLNK(info.external_attr >> 16)
        assert zf.read(info) == b"file.txt"
    skipped = cli("create", "b.zip", "t/flink", "--symlinks", "skip", cwd=workdir)
    assert skipped.returncode == 0, skipped
    assert "skipping t/flink: symbolic link" in skipped.stderr
    followed = cli("create", "c.zip", "t/flink", cwd=workdir)
    with ZipFile(workdir / "c.zip") as zf:
        assert zf.read("t/flink") == b"plain"
    assert followed.returncode == 0


@pytest.mark.usefixtures("tree")
def test_stored_links_are_encrypted_like_files(cli: CliRunner, workdir: Path) -> None:
    result = cli(
        "create", "out.zip", "t", "--symlinks", "store", "--encryption", "aes256",
        env={"ZIPCTL_PASSWORD": PASSWORD}, cwd=workdir,
    )  # fmt: skip
    assert result.returncode == 0, result
    with ZipFile(workdir / "out.zip") as zf:
        link = zf.getinfo("t/flink")
        assert link.is_encrypted
        assert stat.S_ISLNK(link.external_attr >> 16)
        assert zf.read(link, pwd=PASSWORD.encode()) == b"file.txt"
        assert zf.getinfo("t/file.txt").is_encrypted
    checked = cli("test", "out.zip", env={"ZIPCTL_PASSWORD": PASSWORD}, cwd=workdir)
    assert checked.returncode == 0, checked


@pytest.mark.usefixtures("tree")
def test_a_protect_style_rule_can_cover_only_links(
    cli: CliRunner, workdir: Path
) -> None:
    spec = {
        "rules": [
            {"match": "t/flink", "method": "aes256", "password": {"env": "LINK_PW"}}
        ]
    }
    result = cli(
        "create", "out.zip", "t", "--symlinks", "store", "--encryption-spec", "-",
        stdin=json.dumps(spec), env={"LINK_PW": PASSWORD}, cwd=workdir,
    )  # fmt: skip
    assert result.returncode == 0, result
    with ZipFile(workdir / "out.zip") as zf:
        assert zf.getinfo("t/flink").is_encrypted
        assert not zf.getinfo("t/file.txt").is_encrypted


@pytest.mark.usefixtures("tree")
def test_dry_run_shows_the_protection_of_links(cli: CliRunner, workdir: Path) -> None:
    result = cli(
        "create", "out.zip", "t", "--symlinks", "store", "-n", "--encryption", "aes256",
        env={"ZIPCTL_PASSWORD": PASSWORD}, cwd=workdir,
    )  # fmt: skip
    assert result.returncode == 0, result
    assert "Would add: t/flink (symlink, AES-256)" in result.stdout.splitlines()


def test_a_link_that_cannot_be_read_says_why_instead_of_calling_it_broken(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    (tree / "loop-a").symlink_to("loop-b")
    (tree / "loop-b").symlink_to("loop-a")
    code, _, err = make(cli, workdir)
    assert code == 0, err
    assert "skipping t/loop-a: " in err
    assert "skipping t/loop-a: broken symbolic link" not in err
    assert "skipping t/broken: broken symbolic link" in err


@pytest.mark.usefixtures("tree")
def test_exclude_applies_to_links_too(cli: CliRunner, workdir: Path) -> None:
    code, _, err = make(
        cli, workdir, "--symlinks", "store", "--exclude", "*link", "--exclude", "broken"
    )
    assert code == 0, err
    assert links(workdir) == {}


@pytest.mark.usefixtures("tree")
def test_a_stored_link_is_extracted_only_when_the_policy_allows_it(
    cli: CliRunner, workdir: Path
) -> None:
    assert make(cli, workdir, "--symlinks", "store")[0] == 0
    refused = cli("extract", "out.zip", "-d", "plain", cwd=workdir)
    assert refused.returncode == 1, refused
    assert not (workdir / "plain" / "t" / "flink").is_symlink()

    allowed = cli(
        "extract", "out.zip", "-d", "back", "--policy-json",
        '{"allow_symlinks": true}', cwd=workdir,
    )  # fmt: skip
    # only the link that points out of the extraction root is still refused
    assert allowed.returncode == 1, allowed
    assert "FAILED  t/broken" in allowed.stdout
    assert allowed.stdout.count("FAILED") == 1
    assert os.readlink(workdir / "back" / "t" / "flink") == "file.txt"
    assert os.readlink(workdir / "back" / "t" / "dlink") == "real"


@pytest.mark.usefixtures("tree")
def test_list_json_reports_stored_links(cli: CliRunner, workdir: Path) -> None:
    assert make(cli, workdir, "--symlinks", "store")[0] == 0
    document = load_json(cli("list", "out.zip", "--json", cwd=workdir), ListReport)
    flags = {m["name"]: m["is_symlink"] for m in document["members"]}
    assert flags["t/flink"] is True
    assert flags["t/file.txt"] is False


@pytest.mark.usefixtures("tree")
def test_dry_run_marks_links(cli: CliRunner, workdir: Path) -> None:
    code, out, _ = make(cli, workdir, "--symlinks", "store", "-n")
    assert code == 0
    assert "Would add: t/flink (symlink)" in out.splitlines()
    assert not (workdir / "out.zip").exists()


def test_a_link_target_that_is_not_utf8_is_refused(
    cli: CliRunner, workdir: Path
) -> None:
    root = workdir / "t"
    root.mkdir()
    try:
        os.symlink(b"bad\xff", os.fsencode(root / "l"))
    except OSError:
        pytest.skip("file system refuses non-UTF-8 names")
    code, _, err = make(cli, workdir, "--symlinks", "store")
    assert code == 1
    assert "not valid UTF-8" in err
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("tree")
def test_an_unknown_mode_is_a_usage_error(cli: CliRunner, workdir: Path) -> None:
    assert make(cli, workdir, "--symlinks", "chase")[0] == 2


def test_following_a_link_out_of_the_tree_warns(cli: CliRunner, workdir: Path) -> None:
    root = workdir / "t"
    root.mkdir()
    secret = workdir / "secret.txt"
    secret.write_bytes(b"private")
    (root / "inside.txt").write_bytes(b"x")
    (root / "leak").symlink_to(secret)
    (root / "near").symlink_to("inside.txt")
    code, _, err = make(cli, workdir)
    assert code == 0, err
    assert f"t/leak is a symbolic link to {secret.resolve()}, outside" in err
    assert "t/near" not in err
