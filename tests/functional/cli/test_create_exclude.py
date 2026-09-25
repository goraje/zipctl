"""``ziplet create --exclude`` and ``--dry-run``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.support import PASSWORD, Result
from ziplet import ZipFile


@pytest.fixture
def tree(workdir: Path) -> Path:
    root = workdir / "proj"
    for name in (
        "main.py",
        "main.pyc",
        "pkg/mod.py",
        "pkg/mod.pyc",
        "pkg/__pycache__/x.pyc",
        ".git/config",
        "build/out.bin",
        "docs/build.txt",
    ):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"data")
    return root


def created(cli: CliRunner, workdir: Path, *args: str) -> list[str]:
    result = cli("create", "out.zip", "proj", *args, cwd=workdir)
    assert result.returncode == 0, result
    with ZipFile(workdir / "out.zip") as zf:
        return [n for n in zf.namelist() if not n.endswith("/")]


def test_a_name_without_a_slash_matches_at_any_depth(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    files = created(cli, workdir, "--exclude", "*.pyc")
    assert sorted(files) == [
        "proj/.git/config",
        "proj/build/out.bin",
        "proj/docs/build.txt",
        "proj/main.py",
        "proj/pkg/mod.py",
    ]


def test_a_pattern_for_the_contents_leaves_out_the_directory_too(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    created(cli, workdir, "--exclude", "proj/build/**")
    with ZipFile(workdir / "out.zip") as zf:
        assert not [n for n in zf.namelist() if n.startswith("proj/build/")]
        assert "proj/docs/build.txt" in zf.namelist()


def test_a_matching_directory_is_pruned_whole(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    files = created(cli, workdir, "--exclude", ".git", "--exclude", "__pycache__")
    assert not any(".git" in f or "__pycache__" in f for f in files)
    assert "proj/pkg/mod.pyc" in files
    with ZipFile(workdir / "out.zip") as zf:
        assert not any(n.startswith("proj/.git") for n in zf.namelist())


def test_a_pattern_with_a_slash_matches_the_whole_archive_name(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    files = created(cli, workdir, "--exclude", "proj/build")
    assert "proj/build/out.bin" not in files
    assert "proj/docs/build.txt" in files  # only the top-level build/ is named
    files = created(cli, workdir, "--force", "--exclude", "proj/*/*.pyc")
    assert "proj/pkg/mod.pyc" not in files
    assert "proj/main.pyc" in files


def test_an_exclude_that_matches_nothing_warns(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    result = cli("create", "out.zip", "proj", "--exclude", "*.tmp", cwd=workdir)
    assert result.returncode == 0, result
    assert "warning: --exclude '*.tmp' matched nothing" in result.stderr
    assert result.stdout.startswith("\nCreated out.zip")  # blank row after a warning
    quiet = cli("create", "o2.zip", "proj", "--exclude", "*.tmp", "-q", cwd=workdir)
    assert quiet.stderr == ""


def test_json_lists_unused_excludes(cli: CliRunner, workdir: Path, tree: Path) -> None:
    result = cli(
        "create", "out.zip", "proj", "--exclude", "*.tmp", "--exclude", ".git",
        "--json", cwd=workdir,
    )  # fmt: skip
    assert json.loads(result.stdout)["unused_excludes"] == ["*.tmp"]


def test_a_malformed_exclude_is_a_usage_error(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    result = cli("create", "out.zip", "proj", "--exclude", "a**", cwd=workdir)
    assert result.returncode == 2, result
    assert not (workdir / "out.zip").exists()


def test_exclude_applies_to_a_file_named_on_the_command_line(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    result = cli(
        "create", "out.zip", "proj/main.py", "proj/main.pyc", "--exclude", "*.pyc",
        cwd=workdir,
    )  # fmt: skip
    assert result.returncode == 0, result
    with ZipFile(workdir / "out.zip") as zf:
        assert zf.namelist() == ["proj/main.py"]


# --- --dry-run -----------------------------------------------------------------


def test_dry_run_lists_what_would_be_added_and_writes_nothing(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    result = cli("create", "out.zip", "proj/pkg", "--dry-run", cwd=workdir)
    assert result.returncode == 0, result
    lines = result.stdout.splitlines()
    assert "Would add: proj/pkg/ (directory)" in lines
    assert "Would add: proj/pkg/mod.py (deflate, none)" in lines
    assert lines[-1] == "Dry run: would create out.zip: 3 files, 2 directories"
    assert lines[-2] == ""
    assert sorted(p.name for p in workdir.iterdir()) == ["proj"]


def test_dry_run_shows_the_protection_each_file_would_get(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    result = cli(
        "create", "out.zip", "proj/pkg", "-n", "--encryption", "aes256",
        "--protect", "**/*.pyc=none",
        env={"ZIPLET_PASSWORD": PASSWORD}, cwd=workdir,
    )  # fmt: skip
    assert result.returncode == 0, result
    assert "Would add: proj/pkg/mod.py (deflate, AES-256)" in result.stdout
    assert "Would add: proj/pkg/mod.pyc (deflate, none)" in result.stdout


def test_dry_run_json(cli: CliRunner, workdir: Path, tree: Path) -> None:
    result = cli("create", "out.zip", "proj/pkg", "-n", "--json", cwd=workdir)
    document = json.loads(result.stdout)
    assert document["dry_run"] is True
    assert document["appended"] is False
    assert (document["file_count"], document["directory_count"]) == (3, 2)
    assert {
        "name": "proj/pkg/mod.py",
        "directory": False,
        "is_symlink": False,
        "compression": "deflate",
        "encryption": "none",
    } in document["members"]


def test_dry_run_json_names_the_encryption_as_a_real_run_does(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    env = {"ZIPLET_PASSWORD": PASSWORD}
    args = ("proj/pkg", "--json", "--encryption", "aes256")
    dry = cli("create", "out.zip", *args, "-n", env=env, cwd=workdir)
    real = cli("create", "out.zip", *args, env=env, cwd=workdir)

    def encryption(result: Result) -> dict[str, str]:
        members = json.loads(result.stdout)["members"]
        return {m["name"]: m["encryption"] for m in members if not m["directory"]}

    assert encryption(dry) == encryption(real)
    assert set(encryption(dry).values()) == {"AES-256"}


def test_dry_run_still_refuses_an_existing_archive(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    (workdir / "out.zip").write_bytes(b"not touched")
    result = cli("create", "out.zip", "proj", "-n", cwd=workdir)
    assert result.returncode == 1, result
    assert "already exists" in result.stderr
    assert (workdir / "out.zip").read_bytes() == b"not touched"


def test_dry_run_with_append_reports_clashes_and_keeps_the_archive(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    assert cli("create", "out.zip", "proj/main.py", cwd=workdir).returncode == 0
    before = (workdir / "out.zip").read_bytes()
    clash = cli("create", "out.zip", "proj/main.py", "--append", "-n", cwd=workdir)
    assert clash.returncode == 1, clash
    assert "already in the archive" in clash.stderr
    fresh = cli("create", "out.zip", "proj/main.pyc", "--append", "-n", cwd=workdir)
    assert fresh.returncode == 0, fresh
    assert fresh.stdout.splitlines()[-1] == (
        "Dry run: would add to out.zip: 1 file, 0 directories"
    )
    assert (workdir / "out.zip").read_bytes() == before


def test_dry_run_still_rejects_a_dead_protect_rule(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    result = cli(
        "create", "out.zip", "proj/pkg", "-n", "--protect", "nope*=aes256", cwd=workdir
    )
    assert result.returncode != 0, result
    assert not (workdir / "out.zip").exists()


# --- --progress ----------------------------------------------------------------


def test_progress_reports_each_entry_on_standard_error(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    result = cli("create", "out.zip", "proj/pkg", "--progress", cwd=workdir)
    assert result.returncode == 0, result
    lines = result.stderr.splitlines()
    assert lines[0] == "[1/5] OK      proj/pkg/"
    assert lines[-1].startswith("[5/5] OK      proj/pkg/")
    assert len(lines) == 5
    assert result.stdout.startswith("Created out.zip")


def test_without_progress_standard_error_stays_empty(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    assert cli("create", "out.zip", "proj/pkg", cwd=workdir).stderr == ""


def test_progress_does_not_apply_to_a_dry_run(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    result = cli("create", "out.zip", "proj/pkg", "--progress", "-n", cwd=workdir)
    assert result.returncode == 0
    assert result.stderr == ""
