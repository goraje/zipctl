"""``ziplet extract``: safety by default, policies, overwrites, passwords, progress."""

from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

import ziplet
from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.support import (
    HAS_PTY,
    PASSWORD,
    data_offset,
    flip_byte,
    special_info,
    write_archive,
)
from tests.functional.cli.support import run_in_terminal as terminal
from ziplet import ZipFile

PW = PASSWORD.encode()
posix_only = pytest.mark.skipif(os.name != "posix", reason="needs POSIX file types")
S_IFLNK, S_IFIFO, S_IFCHR = 0o120000, 0o010000, 0o020000


def tree(root: Path) -> dict[str, bytes | None]:
    """Everything under *root*: {relative path: content, or None for directories}."""
    found: dict[str, bytes | None] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        found[relative] = path.read_bytes() if path.is_file() else None
    return found


@pytest.fixture
def sample(workdir: Path) -> Path:
    path = workdir / "sample.zip"
    with ZipFile(path, "w", compression=ziplet.ZIP_DEFLATED) as zf:
        zf.mkdir("docs")
        zf.writestr("docs/readme.txt", b"readme " * 20)
        zf.writestr("docs/deep/er/notes.md", b"# notes\n")
        zf.writestr("café.txt", "unicode ☃".encode())
        zf.writestr("empty.txt", b"")
        zf.mkdir("emptydir")
    return path


SAMPLE_TREE = {
    "docs": None,
    "docs/readme.txt": b"readme " * 20,
    "docs/deep": None,
    "docs/deep/er": None,
    "docs/deep/er/notes.md": b"# notes\n",
    "café.txt": "unicode ☃".encode(),
    "empty.txt": b"",
    "emptydir": None,
}


@pytest.fixture
def hostile(workdir: Path) -> Path:
    path = workdir / "hostile.zip"
    with ZipFile(path, "w") as zf:
        zf.writestr("ok.txt", b"fine")
        zf.writestr("../escape.txt", b"escaped")
        zf.writestr("/abs/path.txt", b"absolute")
        zf.writestr(special_info("link", S_IFLNK | 0o777), b"/etc/passwd")
        zf.writestr(special_info("pipe", S_IFIFO | 0o644), b"")
        zf.writestr(special_info("dev", S_IFCHR | 0o600), b"")
    return path


def _json(result: Any) -> dict[str, Any]:
    assert result.stderr == "", result
    document: dict[str, Any] = json.loads(result.stdout)
    return document


def _statuses(document: dict[str, Any]) -> dict[str, str]:
    return {m["member"]: m["status"] for m in document["result"]["members"]}


# --- plain extraction


def test_extracts_everything_with_the_right_content(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    dest = workdir / "out"
    result = cli("extract", str(sample), "-d", str(dest))
    assert result.returncode == 0, result
    assert tree(dest) == SAMPLE_TREE
    assert result.stdout == f"Extracted to {dest}: 6 members (159 B)\n"
    assert result.stderr == ""


def test_the_destination_defaults_to_the_current_directory(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    cwd = workdir / "here"
    cwd.mkdir()
    result = cli("extract", str(sample), cwd=cwd)
    assert result.returncode == 0, result
    assert tree(cwd) == SAMPLE_TREE


def test_missing_destination_directories_are_created(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    dest = workdir / "a" / "b" / "c"
    assert cli("extract", str(sample), "-d", str(dest)).returncode == 0
    assert tree(dest) == SAMPLE_TREE


@posix_only
def test_a_destination_reached_through_a_symlink_works(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    real = workdir / "real"
    real.mkdir()
    link = workdir / "link"
    link.symlink_to(real, target_is_directory=True)
    assert cli("extract", str(sample), "-d", str(link)).returncode == 0
    assert tree(real) == SAMPLE_TREE


def test_destination_with_spaces_and_unicode(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    dest = workdir / "my out é dir"
    assert cli("extract", str(sample), "-d", str(dest)).returncode == 0
    assert tree(dest) == SAMPLE_TREE


def test_an_empty_archive_extracts_nothing_successfully(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(workdir / "e.zip", [])
    result = cli("extract", str(archive), "-d", str(workdir / "out"))
    assert result.returncode == 0
    assert result.stdout.startswith("Extracted to ")


def test_a_large_archive_is_extracted_completely(cli: CliRunner, workdir: Path) -> None:
    files = {f"d{i % 9}/f{i:05d}.txt": f"body {i}".encode() for i in range(2000)}
    archive = write_archive(workdir / "big.zip", list(files.items()))
    dest = workdir / "out"
    result = cli("extract", str(archive), "-d", str(dest))
    assert result.returncode == 0, result
    extracted = {k: v for k, v in tree(dest).items() if v is not None}
    assert extracted == files


def test_every_compression_and_encryption_flavour_extracts(
    cli: CliRunner, workdir: Path
) -> None:
    body = bytes(range(256)) * 40
    flavours = [
        (ziplet.ZIP_STORED, None, None),
        (ziplet.ZIP_DEFLATED, None, None),
        (ziplet.ZIP_BZIP2, None, None),
        (ziplet.ZIP_LZMA, None, None),
        (ziplet.ZIP_DEFLATED, ziplet.WZ_AES, ziplet.ZipFileExtra(wz_aes_nbits=128)),
        (ziplet.ZIP_STORED, ziplet.WZ_AES, ziplet.ZipFileExtra(wz_aes_nbits=192)),
        (
            ziplet.ZIP_DEFLATED,
            ziplet.WZ_AES,
            ziplet.ZipFileExtra(force_wz_aes_version=1),
        ),
        (ziplet.ZIP_DEFLATED, ziplet.ZIP_CRYPTO, None),
    ]
    for index, (compression, encryption, extra) in enumerate(flavours):
        archive = write_archive(
            workdir / f"f{index}.zip",
            [("a.bin", body)],
            compression=compression,
            encryption=encryption,
            password=PW if encryption else None,
            extra=extra,
        )
        dest = workdir / f"out{index}"
        result = cli(
            "extract", str(archive), "-d", str(dest), env={"ZIPLET_PASSWORD": PASSWORD}
        )
        assert result.returncode == 0, (index, result)
        assert (dest / "a.bin").read_bytes() == body


# --- selecting members


def test_only_the_named_members_are_extracted(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    dest = workdir / "out"
    result = cli(
        "extract", str(sample), "docs/readme.txt", "empty.txt", "-d", str(dest)
    )
    assert result.returncode == 0, result
    assert tree(dest) == {
        "docs": None,
        "docs/readme.txt": b"readme " * 20,
        "empty.txt": b"",
    }
    assert ": 2 members (" in result.stdout


def test_repeated_member_names_are_extracted_once(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    result = cli(
        "extract", str(sample), "empty.txt", "empty.txt", "-d", str(workdir / "o")
    )
    assert result.returncode == 0, result
    assert ": 1 member (" in result.stdout


def test_unknown_members_fail_before_anything_is_written(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    dest = workdir / "out"
    result = cli(
        "extract", str(sample), "empty.txt", "nope.txt", "also/missing", "-d", str(dest)
    )
    assert result.returncode == 2, result
    assert "no member matches 'nope.txt', 'also/missing'" in result.stderr
    assert not dest.exists()


def test_member_arguments_are_patterns(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    result = cli("extract", str(sample), "docs/*", "-d", str(workdir / "out"))
    assert result.returncode == 0, result
    assert (workdir / "out" / "docs" / "readme.txt").exists()


def test_a_directory_name_extracts_the_whole_subtree(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    dest = workdir / "out"
    result = cli("extract", str(sample), "docs", "-d", str(dest))
    assert result.returncode == 0, result
    assert tree(dest) == {
        "docs": None,
        "docs/deep": None,
        "docs/deep/er": None,
        "docs/deep/er/notes.md": b"# notes\n",
        "docs/readme.txt": b"readme " * 20,
    }


# --- output modes


def test_verbose_lists_every_member(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    result = cli("extract", "-v", str(sample), "-d", str(workdir / "out"))
    lines = result.stdout.splitlines()
    assert "Extracting: docs/readme.txt" in lines
    assert "Extracting: emptydir/" in lines
    assert len([line for line in lines if line.startswith("Extracting: ")]) == 6


def test_quiet_prints_nothing_on_success(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    result = cli("extract", "-q", str(sample), "-d", str(workdir / "out"))
    assert result.returncode == 0
    assert (result.stdout, result.stderr) == ("", "")


def test_quiet_and_verbose_are_mutually_exclusive(cli: CliRunner, sample: Path) -> None:
    result = cli("extract", "-q", "-v", str(sample))
    assert result.returncode == 2
    assert "not allowed with" in result.stderr


def test_json_report(cli: CliRunner, sample: Path, workdir: Path) -> None:
    dest = workdir / "out"
    document = _json(cli("extract", "--json", str(sample), "-d", str(dest)))
    assert document["archive"] == str(sample)
    assert document["destination"] == str(dest)
    assert (document["policy"], document["dry_run"], document["ok"]) == (
        True,
        False,
        True,
    )
    result = document["result"]
    assert (result["extracted_count"], result["failed_count"]) == (6, 0)
    assert result["bytes_written"] == 159
    by_name = {m["member"]: m for m in result["members"]}
    readme = by_name["docs/readme.txt"]
    assert readme["status"] == "extracted"
    assert Path(readme["target"]) == (dest / "docs" / "readme.txt").resolve()
    assert readme["bytes_written"] == len(b"readme " * 20)
    assert readme["is_directory"] is False
    assert by_name["docs/"]["is_directory"] is True
    assert readme["violations"] == []


def test_json_destination_is_absolute(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    document = _json(
        cli("extract", "--json", str(sample), "-d", "rel-out", cwd=workdir)
    )
    assert document["destination"] == str(workdir / "rel-out")


def test_hostile_names_are_escaped_in_reports_but_exact_in_json(
    cli: CliRunner, workdir: Path
) -> None:
    name = "line1\nline2\x1b[31m.txt"
    archive = write_archive(workdir / "h.zip", [(name, b"x")])
    dest = workdir / "out"
    result = cli("extract", "-v", str(archive), "-d", str(dest))
    assert result.returncode == 0, result
    assert (dest / name).read_bytes() == b"x"
    assert "\x1b" not in result.stdout
    assert "Extracting: line1\\x0aline2\\x1b[31m.txt" in result.stdout
    document = _json(cli("extract", "--json", str(archive), "-d", str(workdir / "o2")))
    assert document["result"]["members"][0]["member"] == name


# --- safety: the default policy


@posix_only
def test_a_hostile_archive_cannot_write_outside_the_destination(
    cli: CliRunner, hostile: Path, workdir: Path
) -> None:
    dest = workdir / "dest"
    before = set(os.listdir(workdir))
    result = cli("extract", str(hostile), "-d", str(dest))
    assert result.returncode == 1, result
    assert set(os.listdir(workdir)) == before | {"dest"}, "something escaped"
    assert tree(dest) == {"ok.txt": b"fine"}
    for name in ("../escape.txt", "/abs/path.txt", "link", "pipe", "dev"):
        assert f"FAILED  {name}: " in result.stdout, name
    assert "parent traversal is not allowed" in result.stdout
    assert "absolute path is not allowed" in result.stdout
    assert "symlink extraction is not allowed" in result.stdout
    assert "special file extraction is not allowed" in result.stdout
    assert ": 1 member (" in result.stdout
    assert ", 5 failed" in result.stdout


@posix_only
def test_json_lists_the_findings_per_member(
    cli: CliRunner, hostile: Path, workdir: Path
) -> None:
    result = cli("extract", "--json", str(hostile), "-d", str(workdir / "dest"))
    assert result.returncode == 1
    document = _json(result)
    assert document["ok"] is False
    assert _statuses(document) == {
        "ok.txt": "extracted",
        "../escape.txt": "failed",
        "/abs/path.txt": "failed",
        "link": "failed",
        "pipe": "failed",
        "dev": "failed",
    }
    codes = {
        m["member"]: {v["code"] for v in m["violations"]}
        for m in document["result"]["members"]
    }
    assert "parent_traversal" in codes["../escape.txt"]
    assert "absolute_path" in codes["/abs/path.txt"]
    assert "symlink" in codes["link"]
    assert "special_file" in codes["pipe"]


def test_no_policy_neutralises_traversal_but_applies_no_limits(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(
        workdir / "t.zip", [("../escape.txt", b"x"), ("ok.txt", b"y")]
    )
    dest = workdir / "dest"
    before = set(os.listdir(workdir))
    result = cli("extract", "--no-policy", str(archive), "-d", str(dest))
    assert result.returncode == 0, result
    assert set(os.listdir(workdir)) == before | {"dest"}
    assert tree(dest) == {"escape.txt": b"x", "ok.txt": b"y"}
    assert result.stdout == f"Extracted to {dest}: 2 members\n"


def test_a_compression_bomb_is_refused_by_default(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(
        workdir / "bomb.zip",
        [("zeros.bin", b"\0" * 3_000_000), ("ok.txt", b"ok")],
        compression=ziplet.ZIP_DEFLATED,
    )
    dest = workdir / "dest"
    result = cli("extract", str(archive), "-d", str(dest))
    assert result.returncode == 1, result
    assert "FAILED  zeros.bin: compression ratio exceeds limit" in result.stdout
    assert tree(dest) == {"ok.txt": b"ok"}
    relaxed = cli(
        "extract", str(archive), "-d", str(workdir / "d2"),
        "--policy-json", '{"max_compression_ratio": null}',
    )  # fmt: skip
    assert relaxed.returncode == 0, relaxed
    assert (workdir / "d2" / "zeros.bin").stat().st_size == 3_000_000


def test_member_size_limit_from_a_policy_file(cli: CliRunner, workdir: Path) -> None:
    archive = write_archive(
        workdir / "s.zip", [("small.txt", b"x" * 10), ("large.txt", b"y" * 500)]
    )
    policy = workdir / "p.json"
    policy.write_text('{"max_member_size": 100}')
    dest = workdir / "dest"
    result = cli("extract", str(archive), "-d", str(dest), "--policy", str(policy))
    assert result.returncode == 1
    assert "FAILED  large.txt: member exceeds size limit" in result.stdout
    assert tree(dest) == {"small.txt": b"x" * 10}


def test_total_size_limit(cli: CliRunner, workdir: Path) -> None:
    archive = write_archive(
        workdir / "t.zip", [("a.txt", b"x" * 400), ("b.txt", b"y" * 400)]
    )
    result = cli(
        "extract", str(archive), "-d", str(workdir / "out"),
        "--policy-json", '{"max_total_uncompressed_size": 500}',
    )  # fmt: skip
    assert result.returncode == 1
    assert "total declared uncompressed size exceeds policy limit" in result.stdout


def test_too_many_entries_rejects_the_whole_archive_once(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(workdir / "m.zip", [(f"f{i}.txt", b"x") for i in range(6)])
    dest = workdir / "dest"
    result = cli(
        "extract", str(archive), "-d", str(dest),
        "--policy-json", '{"max_entries": 3}',
    )  # fmt: skip
    assert result.returncode == 1, result
    assert not dest.exists() or tree(dest) == {}
    assert result.stdout.count("<archive>") == 1
    assert "archive contains 6 entries, limit is 3 [max_entries]" in result.stdout
    assert "FAILED" not in result.stdout
    assert ", 6 failed" in result.stdout


def test_entry_limit_with_skip_keeps_only_the_first_members(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(workdir / "m.zip", [(f"f{i}.txt", b"x") for i in range(6)])
    dest = workdir / "dest"
    result = cli(
        "extract", str(archive), "-d", str(dest),
        "--policy-json", '{"max_entries": 3, "on_violation": "skip"}',
    )  # fmt: skip
    assert result.returncode == 0, result
    assert sorted(tree(dest)) == ["f0.txt", "f1.txt", "f2.txt"]
    assert ", 3 skipped" in result.stdout


def test_a_blocked_compound_extension(cli: CliRunner, workdir: Path) -> None:
    archive = write_archive(
        workdir / "e.zip", [("keep.gz", b"1"), ("drop.tar.gz", b"2"), ("a.txt", b"3")]
    )
    dest = workdir / "dest"
    result = cli(
        "extract", str(archive), "-d", str(dest),
        "--policy-json", '{"blocked_extensions": [".tar.gz"], "on_violation": "skip"}',
    )  # fmt: skip
    assert result.returncode == 0, result
    assert sorted(tree(dest)) == ["a.txt", "keep.gz"]
    assert "SKIP    drop.tar.gz: extension is blocked" in result.stdout


def test_duplicate_targets_are_refused(cli: CliRunner, workdir: Path) -> None:
    import warnings

    path = workdir / "d.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with ZipFile(path, "w") as zf:
            zf.writestr("same.txt", b"first")
            zf.writestr("same.txt", b"second")
    dest = workdir / "dest"
    result = cli("extract", str(path), "-d", str(dest))
    assert result.returncode == 1, result
    assert "duplicates" in result.stdout
    assert tree(dest) == {"same.txt": b"first"}


def test_skip_level_findings_do_not_fail_the_run(
    cli: CliRunner, hostile: Path, workdir: Path
) -> None:
    dest = workdir / "dest"
    result = cli(
        "extract",
        str(hostile),
        "-d",
        str(dest),
        "--policy-json",
        '{"on_violation": "skip"}',
    )
    assert result.returncode == 0, result
    assert tree(dest) == {"ok.txt": b"fine"}
    assert "SKIP    ../escape.txt: parent traversal is not allowed" in result.stdout
    assert ", 5 skipped" in result.stdout
    lenient = write_archive(workdir / "l.zip", [("a.exe", b"1"), ("b.txt", b"2")])
    ok = cli(
        "extract", str(lenient), "-d", str(workdir / "d2"),
        "--policy-json", '{"blocked_extensions": [".exe"], "on_violation": "skip"}',
    )  # fmt: skip
    assert ok.returncode == 0, ok
    assert ", 1 skipped" in ok.stdout


def test_warn_level_findings_are_reported_but_extracted(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(workdir / "w.zip", [("x.exe", b"1"), ("y.txt", b"2")])
    dest = workdir / "dest"
    result = cli(
        "extract", str(archive), "-d", str(dest),
        "--policy-json", '{"blocked_extensions": [".exe"], "on_violation": "warn"}',
    )  # fmt: skip
    assert result.returncode == 0, result
    assert sorted(tree(dest)) == ["x.exe", "y.txt"]
    assert "ziplet: warning: x.exe: extension is blocked" in result.stderr
    assert "Traceback" not in result.stderr
    quiet = cli(
        "extract", "-q", str(archive), "-d", str(workdir / "d2"),
        "--policy-json", '{"blocked_extensions": [".exe"], "on_violation": "warn"}',
    )  # fmt: skip
    assert quiet.stderr == ""


def test_inline_policy_overrides_the_policy_file(cli: CliRunner, workdir: Path) -> None:
    archive = write_archive(workdir / "a.zip", [(f"f{i}", b"x") for i in range(5)])
    policy = workdir / "p.json"
    policy.write_text('{"max_entries": 2}')
    strict = cli(
        "extract", str(archive), "-d", str(workdir / "a"), "--policy", str(policy)
    )
    assert strict.returncode == 1
    layered = cli(
        "extract", str(archive), "-d", str(workdir / "b"), "--policy", str(policy),
        "--policy-json", '{"max_entries": 50}',
    )  # fmt: skip
    assert layered.returncode == 0, layered


def test_policy_from_standard_input(cli: CliRunner, workdir: Path) -> None:
    archive = write_archive(workdir / "a.zip", [("x.exe", b"1"), ("y.txt", b"2")])
    dest = workdir / "dest"
    result = cli(
        "extract", str(archive), "-d", str(dest), "--policy", "-",
        stdin='{"blocked_extensions": [".exe"]}',
    )  # fmt: skip
    assert result.returncode == 1
    assert tree(dest) == {"y.txt": b"2"}


def test_an_invalid_policy_stops_everything_with_exit_2(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    dest = workdir / "dest"
    result = cli(
        "extract", str(sample), "-d", str(dest), "--policy-json", '{"nonsense": 1}'
    )
    assert result.returncode == 2, result
    assert "invalid policy (--policy-json)" in result.stderr
    assert not dest.exists()


def test_policy_and_password_cannot_both_read_standard_input(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(
        workdir / "e.zip", [("a", b"1")], encryption=ziplet.WZ_AES, password=PW
    )
    result = cli(
        "extract", str(archive), "-d", str(workdir / "o"), "--policy", "-",
        "--password-stdin", stdin="{}\n",
    )  # fmt: skip
    assert result.returncode == 2
    assert "standard input cannot be used for both" in result.stderr


# --- overwriting


@pytest.fixture
def two_files(workdir: Path) -> Path:
    return write_archive(
        workdir / "two.zip", [("a.txt", b"NEW a"), ("b.txt", b"NEW b")]
    )


def _existing(workdir: Path) -> Path:
    dest = workdir / "dest"
    dest.mkdir()
    (dest / "a.txt").write_bytes(b"OLD a")
    return dest


def test_existing_files_are_never_overwritten_by_default(
    cli: CliRunner, two_files: Path, workdir: Path
) -> None:
    dest = _existing(workdir)
    result = cli("extract", str(two_files), "-d", str(dest))
    assert result.returncode == 1, result
    assert "FAILED  a.txt: target already exists" in result.stdout
    assert tree(dest) == {"a.txt": b"OLD a", "b.txt": b"NEW b"}


def test_overwrite_skip(cli: CliRunner, two_files: Path, workdir: Path) -> None:
    dest = _existing(workdir)
    result = cli("extract", str(two_files), "-d", str(dest), "--overwrite", "skip")
    assert result.returncode == 0, result
    assert "SKIP    a.txt: target already exists" in result.stdout
    assert tree(dest) == {"a.txt": b"OLD a", "b.txt": b"NEW b"}


def test_overwrite_replace(cli: CliRunner, two_files: Path, workdir: Path) -> None:
    dest = _existing(workdir)
    result = cli("extract", str(two_files), "-d", str(dest), "--overwrite", "replace")
    assert result.returncode == 0, result
    assert tree(dest) == {"a.txt": b"NEW a", "b.txt": b"NEW b"}
    assert not list(dest.glob(".ziplet-*"))


def test_overwrite_rename_keeps_both(
    cli: CliRunner, two_files: Path, workdir: Path
) -> None:
    dest = _existing(workdir)
    result = cli("extract", str(two_files), "-d", str(dest), "--overwrite", "rename")
    assert result.returncode == 0, result
    assert tree(dest) == {"a.txt": b"OLD a", "a.txt.1": b"NEW a", "b.txt": b"NEW b"}


def test_extracting_twice_needs_an_overwrite_choice(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    dest = workdir / "out"
    assert cli("extract", str(sample), "-d", str(dest)).returncode == 0
    again = cli("extract", str(sample), "-d", str(dest))
    assert again.returncode == 1
    assert "target already exists" in again.stdout
    replace = cli("extract", str(sample), "-d", str(dest), "--overwrite", "replace")
    assert replace.returncode == 0, replace
    assert tree(dest) == SAMPLE_TREE


def test_unknown_overwrite_choice_is_a_usage_error(
    cli: CliRunner, sample: Path
) -> None:
    result = cli("extract", str(sample), "--overwrite", "clobber")
    assert result.returncode == 2
    assert "invalid choice" in result.stderr


def test_the_overwrite_flag_beats_the_policy_file(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(workdir / "a.zip", [("a.txt", b"NEW")])
    dest = workdir / "dest"
    dest.mkdir()
    (dest / "a.txt").write_bytes(b"OLD")
    policy = workdir / "p.json"
    policy.write_text('{"overwrite_policy": "skip"}')
    result = cli(
        "extract", str(archive), "-d", str(dest), "--policy", str(policy),
        "--overwrite", "replace",
    )  # fmt: skip
    assert result.returncode == 0
    assert (dest / "a.txt").read_bytes() == b"NEW"


# --- dry runs


def test_a_dry_run_writes_nothing_and_reports_what_would_happen(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    dest = workdir / "dest"
    result = cli("extract", "--dry-run", str(sample), "-d", str(dest))
    assert result.returncode == 0, result
    assert not dest.exists()
    assert result.stdout == f"Dry run: would extract to {dest}: 6 members\n"


def test_a_dry_run_reports_findings_and_fails_like_the_real_run(
    cli: CliRunner, hostile: Path, workdir: Path
) -> None:
    dest = workdir / "dest"
    before = set(os.listdir(workdir))
    result = cli("extract", "--dry-run", str(hostile), "-d", str(dest))
    assert result.returncode == 1, result
    assert set(os.listdir(workdir)) == before
    assert "FAILED  ../escape.txt" in result.stdout
    assert "Dry run: would extract to " in result.stdout


def test_a_dry_run_leaves_existing_content_alone(
    cli: CliRunner, two_files: Path, workdir: Path
) -> None:
    dest = _existing(workdir)
    result = cli(
        "extract",
        "--dry-run",
        str(two_files),
        "-d",
        str(dest),
        "--overwrite",
        "replace",
    )
    assert result.returncode == 0, result
    assert tree(dest) == {"a.txt": b"OLD a"}


def test_dry_run_json_marks_members_as_previewed(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    document = _json(
        cli("extract", "--dry-run", "--json", str(sample), "-d", str(workdir / "d"))
    )
    assert document["dry_run"] is True
    assert set(_statuses(document).values()) == {"previewed"}
    assert not (workdir / "d").exists()


# --- --no-policy and option conflicts


@pytest.mark.parametrize(
    "option",
    [
        ["--policy", "x.json"],
        ["--policy-json", "{}"],
        ["--dry-run"],
        ["--overwrite", "skip"],
        ["--no-fsync"],
    ],
)
def test_no_policy_conflicts_with_options_that_configure_the_policy(
    cli: CliRunner, sample: Path, option: list[str]
) -> None:
    result = cli("extract", "--no-policy", str(sample), *option)
    assert result.returncode == 2, result
    assert f"--no-policy cannot be combined with {option[0]}" in result.stderr


def test_no_fsync_is_accepted(cli: CliRunner, sample: Path, workdir: Path) -> None:
    dest = workdir / "out"
    result = cli("extract", "--no-fsync", str(sample), "-d", str(dest))
    assert result.returncode == 0, result
    assert tree(dest) == SAMPLE_TREE


# --- passwords


@pytest.fixture
def per_member(workdir: Path) -> Path:
    path = workdir / "per.zip"
    with ZipFile(path, "w", encryption=ziplet.WZ_AES) as zf:
        zf.writestr("alpha.txt", b"alpha!", password=b"pass-alpha")
        zf.writestr("beta.txt", b"beta!", password=b"pass-beta")
        zf.writestr("plain.txt", b"plain!", encryption=None)
    return path


def test_encrypted_members_need_a_password_but_others_still_extract(
    cli: CliRunner, per_member: Path, workdir: Path
) -> None:
    dest = workdir / "dest"
    result = cli("extract", str(per_member), "-d", str(dest))
    assert result.returncode == 1, result
    assert tree(dest) == {"plain.txt": b"plain!"}
    assert "FAILED  alpha.txt: " in result.stdout
    assert "password required" in result.stdout
    assert "--password-file" in result.stdout


def test_each_member_gets_its_own_password(
    cli: CliRunner, per_member: Path, workdir: Path
) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(b"pass-alpha\n")
    dest = workdir / "dest"
    result = cli(
        "extract", str(per_member), "-d", str(dest), "--password-file", str(passfile),
        "--password-stdin", stdin="pass-beta\n",
    )  # fmt: skip
    assert result.returncode == 0, result
    assert tree(dest) == {
        "alpha.txt": b"alpha!",
        "beta.txt": b"beta!",
        "plain.txt": b"plain!",
    }


def test_a_wrong_password_fails_only_that_member(
    cli: CliRunner, per_member: Path, workdir: Path
) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(b"pass-alpha\n")
    dest = workdir / "dest"
    result = cli(
        "extract", str(per_member), "-d", str(dest), "--password-file", str(passfile)
    )
    assert result.returncode == 1
    assert tree(dest) == {"alpha.txt": b"alpha!", "plain.txt": b"plain!"}
    assert "FAILED  beta.txt: wrong password" in result.stdout


def test_password_from_the_environment_and_from_stdin(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(
        workdir / "e.zip",
        [("a", b"1"), ("b", b"2")],
        encryption=ziplet.WZ_AES,
        password=PW,
    )
    assert (
        cli(
            "extract",
            str(archive),
            "-d",
            str(workdir / "x"),
            env={"ZIPLET_PASSWORD": PASSWORD},
        ).returncode
        == 0
    )
    assert (
        cli(
            "extract",
            str(archive),
            "-d",
            str(workdir / "y"),
            "--password-stdin",
            stdin=PASSWORD,
        ).returncode
        == 0
    )
    assert tree(workdir / "y") == {"a": b"1", "b": b"2"}


def test_without_a_policy_a_password_problem_is_an_error_message(
    cli: CliRunner, per_member: Path, workdir: Path
) -> None:
    result = cli("extract", "--no-policy", str(per_member), "-d", str(workdir / "d"))
    assert result.returncode == 1, result
    assert "cannot extract: password required" in result.stderr
    assert "Traceback" not in result.stderr


def test_without_a_policy_passwords_still_work(
    cli: CliRunner, per_member: Path, workdir: Path
) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(b"pass-alpha\n")
    result = cli(
        "extract", "--no-policy", str(per_member), "-d", str(workdir / "d"),
        "--password-file", str(passfile), "--password-stdin", stdin="pass-beta\n",
    )  # fmt: skip
    assert result.returncode == 0, result
    assert (workdir / "d" / "beta.txt").read_bytes() == b"beta!"


def test_passwords_never_appear_in_the_output(
    cli: CliRunner, per_member: Path, workdir: Path
) -> None:
    passfile = workdir / "pw"
    passfile.write_bytes(b"pass-alpha\n")
    for extra in ([], ["--json"], ["-v"], ["--progress"]):
        result = cli(
            "extract", *extra, str(per_member), "-d", str(workdir / f"d{len(extra)}"),
            "--password-file", str(passfile), "--password-stdin",
            "--overwrite", "replace",
            stdin="pass-beta\n",
        )  # fmt: skip
        assert "pass-alpha" not in result.stdout + result.stderr
        assert "pass-beta" not in result.stdout + result.stderr


@pytest.mark.skipif(not HAS_PTY, reason="needs a POSIX pseudo-terminal")
def test_prompts_ask_once_per_distinct_password(
    cli: CliRunner, per_member: Path, workdir: Path
) -> None:
    dest = workdir / "dest"
    result, prompts = terminal(
        "extract", str(per_member), "-d", str(dest), replies=["pass-alpha", "pass-beta"]
    )
    assert result.returncode == 0, result
    assert prompts == 2
    assert tree(dest) == {
        "alpha.txt": b"alpha!",
        "beta.txt": b"beta!",
        "plain.txt": b"plain!",
    }
    assert "pass-alpha" not in result.stderr + result.stdout


@pytest.mark.skipif(not HAS_PTY, reason="needs a POSIX pseudo-terminal")
def test_interrupting_a_prompt_stops_cleanly_and_leaves_no_partial_files(
    per_member: Path, workdir: Path
) -> None:
    dest = workdir / "dest"
    result, prompts = terminal(
        "extract", str(per_member), "-d", str(dest), interrupt_at_prompt=1
    )
    assert result.returncode == 130, result
    assert "ziplet: interrupted" in result.stderr
    assert "Traceback" not in result.stderr
    assert not list(dest.rglob(".ziplet-*"))
    assert not (dest / "alpha.txt").exists()


@pytest.mark.skipif(not HAS_PTY, reason="needs a POSIX pseudo-terminal")
def test_wrong_answers_fail_each_member_after_three_tries_of_its_own(
    per_member: Path, workdir: Path
) -> None:
    dest = workdir / "dest"
    result, prompts = terminal(
        "extract", str(per_member), "-d", str(dest), replies=["x", "y", "z"] * 2
    )
    assert result.returncode == 1, result
    assert prompts == 6
    assert "FAILED  alpha.txt: wrong password" in result.stdout
    assert "FAILED  beta.txt: wrong password" in result.stdout
    assert tree(dest) == {"plain.txt": b"plain!"}


@pytest.mark.skipif(not HAS_PTY, reason="needs a POSIX pseudo-terminal")
def test_giving_up_at_the_prompt_fails_the_remaining_encrypted_members(
    per_member: Path, workdir: Path
) -> None:
    dest = workdir / "dest"
    result, prompts = terminal(
        "extract", str(per_member), "-d", str(dest), replies=[""]
    )
    assert result.returncode == 1, result
    assert prompts == 1
    assert tree(dest) == {"plain.txt": b"plain!"}


# --- damaged archives


def test_a_corrupt_member_fails_alone_and_leaves_no_partial_file(
    cli: CliRunner, workdir: Path
) -> None:
    body = b"payload " * 500
    archive = write_archive(
        workdir / "c.zip", [("a.txt", body), ("bad.txt", body), ("z.txt", body)]
    )
    flip_byte(archive, data_offset(archive, "bad.txt") + 9)
    dest = workdir / "dest"
    result = cli("extract", str(archive), "-d", str(dest))
    assert result.returncode == 1, result
    assert sorted(tree(dest)) == ["a.txt", "z.txt"]
    assert "FAILED  bad.txt: " in result.stdout
    assert "CRC" in result.stdout
    assert not list(dest.rglob(".ziplet-*"))
    assert "Traceback" not in result.stderr


def test_a_corrupt_member_without_a_policy_is_an_error_message(
    cli: CliRunner, workdir: Path
) -> None:
    body = b"payload " * 500
    archive = write_archive(workdir / "c.zip", [("bad.txt", body)])
    flip_byte(archive, data_offset(archive, "bad.txt") + 9)
    result = cli("extract", "--no-policy", str(archive), "-d", str(workdir / "d"))
    assert result.returncode == 1
    assert "cannot extract:" in result.stderr
    assert not list((workdir / "d").rglob(".ziplet-*"))
    assert "Traceback" not in result.stderr


def test_bad_archives_fail_cleanly(cli: CliRunner, workdir: Path) -> None:
    missing = cli("extract", str(workdir / "missing.zip"), "-d", str(workdir / "o"))
    assert missing.returncode == 1
    assert "cannot open" in missing.stderr
    junk = workdir / "junk.zip"
    junk.write_bytes(b"not a zip")
    result = cli("extract", str(junk), "-d", str(workdir / "o"))
    assert result.returncode == 1
    assert "not a valid ZIP archive" in result.stderr
    assert not (workdir / "o").exists()


def test_the_destination_being_a_file_is_an_error(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    blocker = workdir / "blocker"
    blocker.write_text("i am a file")
    result = cli("extract", str(sample), "-d", str(blocker))
    assert result.returncode == 1, result
    assert "Traceback" not in result.stderr
    assert blocker.read_text() == "i am a file"


def test_the_archive_is_never_modified(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    before = sample.read_bytes()
    cli("extract", str(sample), "-d", str(workdir / "out"))
    assert sample.read_bytes() == before


# --- progress


def test_progress_prints_one_line_per_finished_member_when_redirected(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    result = cli("extract", "--progress", str(sample), "-d", str(workdir / "out"))
    assert result.returncode == 0, result
    lines = result.stderr.splitlines()
    assert len(lines) == 6
    assert lines[0] == "[1/6] OK      docs/"
    assert lines[-1] == "[6/6] OK      emptydir/"
    assert "\r" not in result.stderr
    assert result.stdout.startswith("Extracted to ")


def test_progress_reports_failures_too(
    cli: CliRunner, hostile: Path, workdir: Path
) -> None:
    result = cli("extract", "--progress", str(hostile), "-d", str(workdir / "out"))
    assert "[1/6] OK      ok.txt" in result.stderr
    assert "[2/6] FAILED  ../escape.txt" in result.stderr


def test_progress_lines_escape_hostile_names(cli: CliRunner, workdir: Path) -> None:
    archive = write_archive(workdir / "h.zip", [("a\x1b[31m\nb.txt", b"x")])
    result = cli("extract", "--progress", str(archive), "-d", str(workdir / "o"))
    assert "\x1b" not in result.stderr
    assert "[1/1] OK      a\\x1b[31m\\x0ab.txt" in result.stderr


class _FakeTerminal(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_on_a_terminal_progress_rewrites_one_status_line_and_clears_it(
    sample: Path,
    workdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from ziplet.cli import main

    terminal_err = _FakeTerminal()
    monkeypatch.setattr(sys, "stderr", terminal_err)
    code = main(["extract", "--progress", str(sample), "-d", str(workdir / "out")])
    assert code == 0
    written = terminal_err.getvalue()
    # first draw, last draw and clear: redraws in between are throttled
    assert written.count("\r") >= 3
    assert "\n" not in written
    assert written.endswith("\r")
    assert "[6/6] emptydir/" in written
    assert "100%" in written
    assert capsys.readouterr().out.startswith("Extracted to ")


def test_files_are_fsynced_by_default_and_not_with_no_fsync(
    sample: Path, workdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ziplet.cli import main

    calls: list[int] = []
    real_fsync = os.fsync

    def counting_fsync(fd: int) -> None:
        calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", counting_fsync)
    assert main(["extract", "-q", str(sample), "-d", str(workdir / "a")]) == 0
    assert calls, "default policy should fsync extracted files"
    calls.clear()
    assert (
        main(["extract", "-q", "--no-fsync", str(sample), "-d", str(workdir / "b")])
        == 0
    )
    assert calls == []


def test_unknown_member_names_are_escaped_in_the_error(
    cli: CliRunner, sample: Path, workdir: Path
) -> None:
    result = cli("extract", str(sample), "bad\x1b[2Jname\n", "-d", str(workdir / "o"))
    assert result.returncode == 2
    assert "\x1b" not in result.stderr
    assert "bad\\x1b[2Jname\\x0a" in result.stderr
