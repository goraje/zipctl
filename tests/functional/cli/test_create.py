"""``zipctl create``: collecting files, compression, replacing, atomicity."""

from __future__ import annotations

import os
import re
import stat
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from typing_extensions import Unpack

from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.support import Result, RunOptions, load_json
from zipctl import ZipFile
from zipctl.cli.commands import create
from zipctl.cli.commands.helpers.collect import Entry
from zipctl.cli.reports import CreateReport
from zipctl.compression import registry

posix_only = pytest.mark.skipif(os.name != "posix", reason="needs POSIX file types")


@pytest.fixture
def source(workdir: Path) -> Path:
    root = workdir / "src"
    (root / "docs" / "deep").mkdir(parents=True)
    (root / "empty").mkdir()
    (root / "a.txt").write_bytes(b"alpha\n" * 50)
    (root / "docs" / "b.md").write_bytes(b"# beta\n")
    (root / "docs" / "deep" / "c.bin").write_bytes(bytes(range(256)) * 20)
    (root / "zero.txt").write_bytes(b"")
    (root / "café ☃.txt").write_bytes(b"unicode")
    return root


EXPECTED = {
    "src/a.txt": b"alpha\n" * 50,
    "src/docs/b.md": b"# beta\n",
    "src/docs/deep/c.bin": bytes(range(256)) * 20,
    "src/zero.txt": b"",
    "src/café ☃.txt": b"unicode",
}
EXPECTED_DIRS = {"src/", "src/docs/", "src/docs/deep/", "src/empty/"}


def contents(path: Path, password: bytes | None = None) -> dict[str, bytes]:
    """Every file in the archive, read with zipctl itself."""
    with ZipFile(path) as zf:
        return {
            info.filename: zf.read(info, pwd=password)
            for info in zf.infolist()
            if not info.is_dir()
        }


def names(path: Path) -> list[str]:
    with ZipFile(path) as zf:
        return zf.namelist()


def leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.startswith(".zipctl-"))


def make(cli: CliRunner, workdir: Path, *args: str, **kw: Unpack[RunOptions]) -> Result:
    """``zipctl create out.zip ARGS``, run in *workdir* (where ``src`` lives)."""
    kw.setdefault("cwd", workdir)
    return cli("create", str(workdir / "out.zip"), *args, **kw)


# --- what gets stored


@pytest.mark.usefixtures("source")
def test_a_directory_tree_round_trips(cli: CliRunner, workdir: Path) -> None:
    result = make(cli, workdir, "src")
    assert result.returncode == 0, result
    archive = workdir / "out.zip"
    assert contents(archive) == EXPECTED
    assert set(names(archive)) - set(EXPECTED) == EXPECTED_DIRS
    assert result.stdout.startswith(f"Created {archive}: 5 files, 4 directories (")
    assert result.stderr == ""
    assert re.search(
        r"\(\d+(\.\d)? (B|KiB), \d+(\.\d)? (B|KiB) compressed\)$", result.stdout.strip()
    )


@pytest.mark.usefixtures("source")
def test_the_standard_library_reads_what_we_write(
    cli: CliRunner, workdir: Path
) -> None:
    make(cli, workdir, "src")
    with zipfile.ZipFile(workdir / "out.zip") as zf:
        assert zf.testzip() is None
        assert {
            i.filename: zf.read(i) for i in zf.infolist() if not i.is_dir()
        } == EXPECTED


@pytest.mark.usefixtures("source")
def test_the_result_extracts_and_tests_clean_with_our_own_commands(
    cli: CliRunner, workdir: Path
) -> None:
    make(cli, workdir, "src")
    assert cli("test", str(workdir / "out.zip")).returncode == 0
    out = workdir / "out"
    assert cli("extract", str(workdir / "out.zip"), "-d", str(out)).returncode == 0
    assert (out / "src" / "docs" / "deep" / "c.bin").read_bytes() == EXPECTED[
        "src/docs/deep/c.bin"
    ]
    assert (out / "src" / "empty").is_dir()


def test_single_files_are_stored_under_the_path_given(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "one.txt").write_bytes(b"1")
    (workdir / "sub").mkdir()
    (workdir / "sub" / "two.txt").write_bytes(b"2")
    result = make(cli, workdir, "one.txt", "sub/two.txt")
    assert result.returncode == 0, result
    assert names(workdir / "out.zip") == ["one.txt", "sub/two.txt"]


def test_dot_stores_the_contents_of_the_directory(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    result = make(cli, workdir, ".", cwd=source)
    assert result.returncode == 0, result
    assert set(contents(workdir / "out.zip")) == {
        n.removeprefix("src/") for n in EXPECTED
    }


def test_c_chooses_the_base_directory(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    result = make(cli, workdir, "-C", str(source), "docs", "a.txt")
    assert result.returncode == 0, result
    assert names(workdir / "out.zip") == [
        "docs/",
        "docs/deep/",
        "docs/b.md",
        "docs/deep/c.bin",
        "a.txt",
    ]


def test_c_must_be_a_directory(cli: CliRunner, workdir: Path, source: Path) -> None:
    result = make(cli, workdir, "-C", str(source / "a.txt"), "x")
    assert result.returncode == 2
    assert "is not a directory" in result.stderr


def test_absolute_paths_are_stored_without_the_root(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    make(cli, workdir, str(source / "a.txt"))
    (stored,) = names(workdir / "out.zip")
    assert not stored.startswith("/")
    assert stored.endswith("src/a.txt")


def test_paths_that_climb_out_are_refused(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    inner = source / "docs"
    result = make(cli, workdir, "../a.txt", cwd=inner)
    assert result.returncode == 1, result
    assert "outside the current directory" in result.stderr
    assert "-C DIR" in result.stderr
    assert not (workdir / "out.zip").exists()
    also = make(cli, workdir, "..", cwd=inner)
    assert also.returncode == 1
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("source")
def test_a_missing_path_fails_before_anything_is_written(
    cli: CliRunner, workdir: Path
) -> None:
    result = make(cli, workdir, "src", str(workdir / "missing"))
    assert result.returncode == 1, result
    assert "cannot read" in result.stderr
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


@pytest.mark.usefixtures("source")
def test_repeated_and_overlapping_paths_are_stored_once(
    cli: CliRunner, workdir: Path
) -> None:
    result = make(cli, workdir, "src", "src/a.txt", "./src/../src", "src/")
    assert result.returncode == 0, result
    listed = names(workdir / "out.zip")
    assert len(listed) == len(set(listed))
    assert listed.count("src/a.txt") == 1


def test_names_and_contents_of_unusual_files(cli: CliRunner, workdir: Path) -> None:
    tree = workdir / "odd"
    tree.mkdir()
    (tree / "with space.txt").write_bytes(b"s")
    unusual_name = "[brackets].txt" if os.name == "nt" else "[brackets]*?.txt"
    (tree / unusual_name).write_bytes(b"b")
    (tree / ".hidden").write_bytes(b"h")
    (tree / "big.bin").write_bytes(os.urandom(3 * 1024 * 1024))
    result = make(cli, workdir, str(tree))
    assert result.returncode == 0, result
    stored = contents(workdir / "out.zip")
    assert {Path(n).name for n in stored} == {
        "with space.txt",
        unusual_name,
        ".hidden",
        "big.bin",
    }
    big = next(v for n, v in stored.items() if n.endswith("big.bin"))
    assert big == (tree / "big.bin").read_bytes()


def test_files_older_than_1980_are_stored_with_a_clamped_date(
    cli: CliRunner, workdir: Path
) -> None:
    old = workdir / "old.txt"
    old.write_bytes(b"x")
    os.utime(old, (0, 0))
    result = make(cli, workdir, "old.txt")
    assert result.returncode == 0, result
    with ZipFile(workdir / "out.zip") as zf:
        assert zf.getinfo("old.txt").date_time[0] == 1980


@posix_only
def test_modes_are_kept(cli: CliRunner, workdir: Path) -> None:
    script = workdir / "run.sh"
    script.write_bytes(b"#!/bin/sh\n")
    script.chmod(0o755)
    make(cli, workdir, "run.sh")
    with ZipFile(workdir / "out.zip") as zf:
        assert (zf.getinfo("run.sh").external_attr >> 16) & 0o777 == 0o755


@posix_only
def test_symlinks_to_files_are_stored_as_their_content(
    cli: CliRunner, workdir: Path
) -> None:
    tree = workdir / "t"
    tree.mkdir()
    (tree / "real.txt").write_bytes(b"real")
    (tree / "link.txt").symlink_to("real.txt")
    result = make(cli, workdir, str(tree))
    assert result.returncode == 0, result
    stored = contents(workdir / "out.zip")
    assert stored[next(n for n in stored if n.endswith("link.txt"))] == b"real"
    with ZipFile(workdir / "out.zip") as zf:
        assert not any(stat.S_ISLNK(i.external_attr >> 16) for i in zf.infolist())


@posix_only
def test_symlinked_directories_broken_links_and_fifos_are_skipped_with_a_warning(
    cli: CliRunner, workdir: Path
) -> None:
    tree = workdir / "t"
    (tree / "real").mkdir(parents=True)
    (tree / "real" / "f.txt").write_bytes(b"f")
    (tree / "dirlink").symlink_to("real", target_is_directory=True)
    (tree / "broken").symlink_to("nowhere")
    os.mkfifo(tree / "pipe")
    result = make(cli, workdir, str(tree))
    assert result.returncode == 0, result
    assert sorted(n for n in names(workdir / "out.zip") if not n.endswith("/")) == [
        f"{str(tree).lstrip('/')}/real/f.txt"
    ]
    for name, reason in (
        ("dirlink", "symbolic link to a directory"),
        ("broken", "broken symbolic link"),
        ("pipe", "not a regular file"),
    ):
        assert f"skipping {tree / name}: {reason}" in result.stderr
    quiet = make(cli, workdir, str(tree), "--force", "-q")
    assert quiet.stderr == ""


@posix_only
def test_a_named_fifo_is_an_error_not_a_hang(cli: CliRunner, workdir: Path) -> None:
    os.mkfifo(workdir / "pipe")
    result = make(cli, workdir, str(workdir / "pipe"))
    assert result.returncode == 1, result
    assert "not a regular file or directory" in result.stderr
    assert not (workdir / "out.zip").exists()


@pytest.mark.usefixtures("workdir")
def test_the_archive_is_never_added_to_itself(cli: CliRunner, source: Path) -> None:
    target = source / "self.zip"
    result = cli("create", str(target), str(source))
    assert result.returncode == 0, result
    assert not any(n.endswith("self.zip") for n in names(target))
    again = cli("create", str(target), str(source), "--force")
    assert again.returncode == 0
    assert not any(n.endswith("self.zip") for n in names(target))
    assert leftovers(source) == []


@posix_only
def test_a_file_name_that_is_not_utf8_is_refused_cleanly(
    cli: CliRunner, workdir: Path
) -> None:
    bad = os.fsencode(workdir) + b"/bad\xffname"
    try:
        with open(bad, "wb") as handle:
            handle.write(b"x")
    except OSError:
        pytest.skip("the file system refuses non-UTF-8 names")
    result = make(cli, workdir, os.fsdecode(bad))
    assert result.returncode == 1, result
    assert "not valid UTF-8" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (workdir / "out.zip").exists()


# --- compression


@pytest.mark.usefixtures("source")
@pytest.mark.parametrize(
    ("method", "code"),
    [("store", 0), ("deflate", 8), ("bzip2", 12), ("lzma", 14), ("zstd", 93)],
)
def test_every_compression_method(
    cli: CliRunner, workdir: Path, method: str, code: int
) -> None:
    if code == 93 and registry._registry.get(93) is None:
        result = make(cli, workdir, "src", "--compression", "zstd")
        assert result.returncode == 2
        assert "zipctl[zstd]" in result.stderr
        return
    result = make(cli, workdir, "src", "--compression", method)
    assert result.returncode == 0, result
    with ZipFile(workdir / "out.zip") as zf:
        assert {
            i.compress_type for i in zf.infolist() if i.file_size and not i.is_dir()
        } == {code}
    assert contents(workdir / "out.zip") == EXPECTED


def test_deflate_is_the_default_and_store_really_stores(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "z.txt").write_bytes(b"0" * 10000)
    make(cli, workdir, "z.txt")
    with ZipFile(workdir / "out.zip") as zf:
        deflated = zf.getinfo("z.txt")
    assert deflated.compress_type == 8
    assert deflated.compress_size < 100
    make(cli, workdir, "z.txt", "--compression", "store", "--force")
    with ZipFile(workdir / "out.zip") as zf:
        assert zf.getinfo("z.txt").compress_size == 10000


def test_the_level_changes_the_size(cli: CliRunner, workdir: Path) -> None:
    (workdir / "r.bin").write_bytes((bytes(range(200)) * 500) + os.urandom(1000))
    sizes = {}
    for level in ("1", "9"):
        assert make(cli, workdir, "r.bin", "-L", level, "--force").returncode == 0
        with ZipFile(workdir / "out.zip") as zf:
            sizes[level] = zf.getinfo("r.bin").compress_size
    assert 0 < sizes["9"] < sizes["1"]


def test_an_unknown_method_is_a_usage_error(cli: CliRunner, workdir: Path) -> None:
    result = make(cli, workdir, "x", "--compression", "rot13")
    assert result.returncode == 2
    assert "invalid choice" in result.stderr


# --- comment


def test_comment(cli: CliRunner, workdir: Path) -> None:
    (workdir / "c.txt").write_bytes(b"x")
    assert make(cli, workdir, "c.txt", "--comment", "héllo").returncode == 0
    with ZipFile(workdir / "out.zip") as zf:
        assert zf.comment.decode() == "héllo"


@pytest.mark.skipif(os.name == "nt", reason="oversized arguments exceed Windows limits")
def test_oversized_comment(cli: CliRunner, workdir: Path) -> None:
    (workdir / "c.txt").write_bytes(b"x")
    too_long = make(
        cli, workdir, "c.txt", "--comment", "x" * 70000, "--force", cwd=workdir
    )
    assert too_long.returncode == 2
    assert "too long" in too_long.stderr


# An end record (22 bytes, comment size 0x0101) whose comment ends where ours does.
FORGED = "PK\x05\x06" + "A" * 16 + "\x01\x01" + "B" * 257


def test_a_comment_holding_an_end_record_is_a_usage_error(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "c.txt").write_bytes(b"x")
    forged = make(cli, workdir, "c.txt", "--comment", FORGED)
    assert forged.returncode == 2
    assert "end of central directory record" in forged.stderr
    assert not (workdir / "out.zip").exists()
    assert make(cli, workdir, "c.txt").returncode == 0
    before = (workdir / "out.zip").read_bytes()
    (workdir / "d.txt").write_bytes(b"y")
    appended = make(cli, workdir, "d.txt", "--append", "--comment", FORGED)
    assert appended.returncode == 2
    assert (workdir / "out.zip").read_bytes() == before
    assert not list(workdir.glob(".zipctl-*"))


# --- an existing archive


@pytest.mark.usefixtures("source")
def test_an_existing_archive_is_refused_and_left_alone(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "out.zip").write_bytes(b"precious")
    result = make(cli, workdir, "src")
    assert result.returncode == 1, result
    assert "already exists" in result.stderr
    assert "--force" in result.stderr
    assert (workdir / "out.zip").read_bytes() == b"precious"
    assert leftovers(workdir) == []


@pytest.mark.usefixtures("source")
def test_force_replaces(cli: CliRunner, workdir: Path) -> None:
    (workdir / "out.zip").write_bytes(b"old")
    assert make(cli, workdir, "src", "--force").returncode == 0
    assert contents(workdir / "out.zip") == EXPECTED


@pytest.mark.usefixtures("source")
def test_a_failed_forced_run_keeps_the_old_archive(
    cli: CliRunner, workdir: Path
) -> None:
    make(cli, workdir, "src")
    before = (workdir / "out.zip").read_bytes()
    result = make(cli, workdir, "src", str(workdir / "missing"), "--force")
    assert result.returncode == 1
    assert (workdir / "out.zip").read_bytes() == before
    assert leftovers(workdir) == []


@pytest.mark.skipif(
    os.name != "posix" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs permissions to matter",
)
def test_a_failure_in_the_middle_of_writing_leaves_no_partial_archive(
    cli: CliRunner, workdir: Path
) -> None:
    tree = workdir / "t"
    tree.mkdir()
    (tree / "a.txt").write_bytes(b"a")
    locked = tree / "b.txt"
    locked.write_bytes(b"b")
    locked.chmod(0)
    try:
        result = make(cli, workdir, str(tree))
    finally:
        locked.chmod(0o644)
    assert result.returncode == 1, result
    assert "cannot add" in result.stderr
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


def test_append_adds_and_keeps_what_was_there(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    assert make(cli, workdir, "a.txt", "-C", str(source)).returncode == 0
    result = make(cli, workdir, "docs", "--append", "-C", str(source))
    assert result.returncode == 0, result
    assert result.stdout.startswith("Added 2 files, 2 directories")
    assert result.stdout.rstrip().endswith(f"to {workdir / 'out.zip'}")
    assert set(contents(workdir / "out.zip")) == {
        "a.txt",
        "docs/b.md",
        "docs/deep/c.bin",
    }
    assert cli("test", str(workdir / "out.zip")).returncode == 0


def test_append_to_a_missing_archive_creates_it(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    result = make(cli, workdir, "a.txt", "--append", "-C", str(source))
    assert result.returncode == 0, result
    assert set(contents(workdir / "out.zip")) == {"a.txt"}


def test_append_to_an_archive_broken_after_the_check_is_reported(
    cli: CliRunner, workdir: Path, source: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (workdir / "out.zip").write_bytes(b"not a zip")

    def checked(
        _args: object, entries: list[Entry], _ctx: object
    ) -> tuple[bool, list[Entry]]:
        return True, entries  # as if the archive changed after the check

    monkeypatch.setattr(create, "_check_target", checked)
    result = make(cli, workdir, "a.txt", "--append", "-C", str(source))
    assert result.returncode == 1, result
    assert "not a valid ZIP archive" in result.stderr
    assert "unexpected" not in result.stderr
    assert (workdir / "out.zip").read_bytes() == b"not a zip"


def test_append_does_not_treat_a_directory_already_in_the_archive_as_a_clash(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    assert make(cli, workdir, "src/docs").returncode == 0
    (source / "docs" / "new.txt").write_bytes(b"new")
    result = make(
        cli,
        workdir,
        "src/docs",
        "--append",
        "--exclude",
        "b.md",
        "--exclude",
        "deep",
    )
    assert result.returncode == 0, result
    listed = names(workdir / "out.zip")
    assert listed.count("src/docs/") == 1
    assert "src/docs/new.txt" in listed


@pytest.mark.usefixtures("source")
@pytest.mark.parametrize("how", ["itself", "hard-link"])
def test_the_archive_being_replaced_is_not_added_to_itself(
    cli: CliRunner, workdir: Path, how: str
) -> None:
    assert make(cli, workdir, "src/a.txt").returncode == 0
    others = []
    if how == "hard-link":
        os.link(workdir / "out.zip", workdir / "copy.zip")
        others = ["copy.zip"]
    result = make(cli, workdir, "src/a.txt", "out.zip", *others, "--force")
    assert result.returncode == 0, result
    assert names(workdir / "out.zip") == ["src/a.txt"]


def test_append_refuses_names_already_present_and_changes_nothing(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    make(cli, workdir, "a.txt", "-C", str(source))
    before = (workdir / "out.zip").read_bytes()
    result = make(cli, workdir, "a.txt", "docs", "--append", "-C", str(source))
    assert result.returncode == 1, result
    assert "already in the archive: 'a.txt'" in result.stderr
    assert (workdir / "out.zip").read_bytes() == before


def test_append_keeps_the_original_when_it_fails(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    make(cli, workdir, "a.txt", "-C", str(source))
    before = (workdir / "out.zip").read_bytes()
    result = make(
        cli, workdir, "docs", str(workdir / "nope"), "--append", "-C", str(source)
    )
    assert result.returncode == 1
    assert (workdir / "out.zip").read_bytes() == before
    assert leftovers(workdir) == []


def test_append_does_not_need_the_password_of_existing_encrypted_members(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    env = {"ZIPCTL_PASSWORD": "pw"}
    assert (
        make(
            cli, workdir, "a.txt", "-C", str(source), "--encryption", "aes256", env=env
        ).returncode
        == 0
    )
    assert make(cli, workdir, "docs", "--append", "-C", str(source)).returncode == 0
    with ZipFile(workdir / "out.zip") as zf:
        assert zf.getinfo("a.txt").is_encrypted
        assert not zf.getinfo("docs/b.md").is_encrypted
    assert contents(workdir / "out.zip", b"pw")["a.txt"] == EXPECTED["src/a.txt"]


def test_force_and_append_conflict(cli: CliRunner, workdir: Path) -> None:
    result = make(cli, workdir, "x", "--force", "--append")
    assert result.returncode == 2
    assert "not allowed with" in result.stderr


@posix_only
def test_the_archive_gets_ordinary_permissions(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    mask = os.umask(0o022)  # read the mask; the child process inherits it
    os.umask(mask)
    result = make(cli, workdir, str(source / "a.txt"))
    assert result.returncode == 0, result
    # what open(..., "w") would give, not the 0600 of the scratch file
    assert stat.S_IMODE(os.stat(workdir / "out.zip").st_mode) == 0o666 & ~mask


@pytest.mark.usefixtures("source")
def test_the_archive_directory_must_exist(cli: CliRunner, workdir: Path) -> None:
    result = cli("create", str(workdir / "nodir" / "out.zip"), "src", cwd=workdir)
    assert result.returncode == 1, result
    assert "cannot create" in result.stderr


# --- output


@pytest.mark.usefixtures("source")
def test_verbose_lists_each_member(cli: CliRunner, workdir: Path) -> None:
    result = make(cli, workdir, "src", "-v")
    lines = result.stdout.splitlines()
    assert "Adding: src/a.txt (deflate, none)" in lines
    assert "Adding: src/docs/ (directory)" in lines
    assert lines[-1].startswith("Created ")
    assert lines[-2] == ""
    assert "" not in lines[:-2]


@pytest.mark.usefixtures("source")
def test_quiet_prints_nothing(cli: CliRunner, workdir: Path) -> None:
    result = make(cli, workdir, "src", "-q")
    assert (result.returncode, result.stdout, result.stderr) == (0, "", "")


@pytest.mark.usefixtures("source")
def test_json_report(cli: CliRunner, workdir: Path) -> None:
    result = make(cli, workdir, "src", "--json", "--compression", "store")
    assert result.returncode == 0
    assert result.stderr == ""
    document = load_json(result, CreateReport)
    assert document["ok"] is True
    assert document["archive"] == str(workdir / "out.zip")
    assert (
        document["appended"],
        document["file_count"],
        document["directory_count"],
    ) == (False, 5, 4)
    assert document["bytes_in"] == sum(len(v) for v in EXPECTED.values())
    by_name = {m["name"]: m for m in document["members"]}
    a = by_name["src/a.txt"]
    assert (a["directory"], a["size"], a["compression"], a["encryption"]) == (
        False,
        300,
        "store",
        "none",
    )
    assert by_name["src/docs/"]["directory"] is True
    assert document["skipped"] == []


def test_hostile_names_are_escaped_in_reports(cli: CliRunner, workdir: Path) -> None:
    tree = workdir / "t"
    tree.mkdir()
    name = "evil\x1b[31mname"
    try:
        (tree / name).write_bytes(b"x")
    except OSError:
        pytest.skip("the file system refuses control characters in names")
    result = make(cli, workdir, str(tree), "-v")
    assert "\x1b" not in result.stdout + result.stderr
    assert "evil\\x1b[31mname" in result.stdout
    document = load_json(
        make(cli, workdir, str(tree), "--json", "--force"), CreateReport
    )
    assert any(m["name"].endswith(name) for m in document["members"])


def test_the_help_lists_the_command(cli: CliRunner) -> None:
    assert "create" in cli("--help").stdout
    text = cli("create", "--help").stdout
    for flag in (
        "--encryption",
        "--protect",
        "--encryption-spec",
        "--append",
        "--force",
    ):
        assert flag in text
    assert "fips" not in text.lower()


@pytest.mark.usefixtures("source")
def test_members_are_added_in_sorted_order_whatever_the_file_system_returns(
    workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zipctl.cli import main

    real_walk = os.walk

    def backwards(
        top: str, *, onerror: Callable[[OSError], None] | None = None
    ) -> Iterator[tuple[str, list[str], list[str]]]:
        for root, dirs, files in real_walk(top, onerror=onerror):
            dirs.sort(reverse=True)
            files.sort(reverse=True)
            yield root, dirs, files

    monkeypatch.setattr(os, "walk", backwards)
    monkeypatch.chdir(workdir)
    assert main(["create", "-q", "out.zip", "src"]) == 0
    listed = names(workdir / "out.zip")
    assert listed == [
        "src/",
        "src/docs/",
        "src/empty/",
        "src/a.txt",
        "src/caf\u00e9 \u2603.txt",
        "src/zero.txt",
        "src/docs/deep/",
        "src/docs/b.md",
        "src/docs/deep/c.bin",
    ]


def test_a_comment_is_applied_when_appending(cli: CliRunner, workdir: Path) -> None:
    (workdir / "a.txt").write_bytes(b"a")
    (workdir / "b.txt").write_bytes(b"b")
    assert make(cli, workdir, "a.txt", "--comment", "first").returncode == 0
    result = make(cli, workdir, "b.txt", "--append", "--comment", "second")
    assert result.returncode == 0, result
    with ZipFile(workdir / "out.zip") as zf:
        assert zf.comment == b"second"
        assert zf.namelist() == ["a.txt", "b.txt"]


@pytest.mark.skipif(os.name == "nt", reason="Windows argv replaces lone surrogates")
def test_a_comment_that_is_not_utf8_is_a_usage_error(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "c.txt").write_bytes(b"x")
    result = make(cli, workdir, "c.txt", "--comment", "a\udcffb")
    assert result.returncode == 2, result
    assert "not valid UTF-8" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    ("method", "level", "message"),
    [
        ("deflate", "10", "out of range for deflate (-1 to 9)"),
        ("bzip2", "0", "out of range for bzip2 (1 to 9)"),
        ("store", "1", "takes no --level"),
        ("lzma", "1", "takes no --level"),
    ],
)
def test_a_level_the_method_cannot_use_is_a_usage_error(
    cli: CliRunner, workdir: Path, method: str, level: str, message: str
) -> None:
    (workdir / "r.txt").write_bytes(b"x")
    result = make(cli, workdir, "r.txt", "--compression", method, "-L", level)
    assert result.returncode == 2, result
    assert message in result.stderr
    assert "Traceback" not in result.stderr
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


@posix_only
def test_an_unreadable_directory_is_an_error_not_a_gap(
    cli: CliRunner, workdir: Path, source: Path
) -> None:
    locked = source / "docs"
    locked.chmod(0)
    try:
        if os.access(locked, os.R_OK):
            pytest.skip("permissions are not enforced (running as root?)")
        result = make(cli, workdir, "src")
    finally:
        locked.chmod(0o755)
    assert result.returncode == 1, result
    assert "cannot read" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (workdir / "out.zip").exists()
    assert leftovers(workdir) == []


@posix_only
def test_appending_through_a_symlink_keeps_the_link(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "a.txt").write_bytes(b"a")
    (workdir / "b.txt").write_bytes(b"b")
    real = workdir / "real.zip"
    assert cli("create", str(real), "a.txt", cwd=workdir).returncode == 0
    link = workdir / "link.zip"
    link.symlink_to(real)
    result = cli("create", str(link), "b.txt", "--append", cwd=workdir)
    assert result.returncode == 0, result
    assert link.is_symlink()
    assert names(real) == ["a.txt", "b.txt"]


@posix_only
def test_a_replace_that_fails_is_reported_not_a_traceback(
    cli: CliRunner, workdir: Path
) -> None:
    (workdir / "a.txt").write_bytes(b"a")
    (workdir / "out.zip").mkdir()
    result = make(cli, workdir, "a.txt", "--force")
    assert result.returncode == 1, result
    assert result.stderr.startswith("zipctl: error: cannot replace ")
    assert "Traceback" not in result.stderr
    assert leftovers(workdir) == []
