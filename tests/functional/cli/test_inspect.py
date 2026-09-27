"""``ziplet inspect``: metadata-only reporting of what extraction would flag."""

from __future__ import annotations

import json
import warnings
from collections.abc import Mapping
from pathlib import Path

import pytest

import ziplet
from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.reports import InspectReport, load_json
from tests.functional.cli.support import (
    PASSWORD,
    Result,
    data_offset,
    flip_byte,
    special_info,
    write_archive,
)
from ziplet import ZipFile
from ziplet.cli.output import JsonValue

S_IFLNK, S_IFIFO, S_IFCHR = 0o120000, 0o010000, 0o020000


@pytest.fixture
def dest(workdir: Path) -> Path:
    return workdir / "dest"


@pytest.fixture
def clean_archive(workdir: Path) -> Path:
    return write_archive(
        workdir / "clean.zip",
        [
            ("readme.txt", b"hello"),
            ("src/main.py", b"print(1)\n"),
            ("data.csv", b"1,2\n"),
        ],
    )  # fmt: skip


@pytest.fixture
def hostile_archive(workdir: Path) -> Path:
    path = workdir / "hostile.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with ZipFile(path, "w") as zf:
            zf.writestr("ok.txt", b"fine")
            zf.writestr("../escape.txt", b"x")
            zf.writestr("/abs/path.txt", b"x")
            zf.writestr(special_info("link", S_IFLNK | 0o777), b"ok.txt")
            zf.writestr(special_info("pipe", S_IFIFO | 0o644), b"")
            zf.writestr(special_info("dev", S_IFCHR | 0o600), b"")
            zf.writestr("dup.txt", b"1")
            zf.writestr("dup.txt", b"2")
    return path


def _json(result: Result) -> InspectReport:
    assert result.stderr == "", result
    return load_json(result, InspectReport)


def _codes(document: InspectReport) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for violation in document["inspection"]["violations"]:
        found.setdefault(violation["member"], set()).add(violation["code"])
    return found


# --- clean archives ------------------------------------------------------------


def test_clean_archive_passes(cli: CliRunner, clean_archive: Path, dest: Path) -> None:
    result = cli("inspect", "-d", str(dest), str(clean_archive))
    assert result.returncode == 0, result
    lines = result.stdout.splitlines()
    assert lines[0] == f"Archive:      {clean_archive}"
    assert lines[1] == f"Destination:  {dest}"
    assert lines[2] == "Members:      3 (0 directories)"
    assert lines[3].startswith("Size:         ")
    assert lines[4] == "Result:       OK"
    assert len(lines) == 5
    assert "Violations" not in result.stdout


def test_inspection_is_read_only_and_creates_nothing(
    cli: CliRunner, clean_archive: Path, dest: Path
) -> None:
    before = clean_archive.read_bytes()
    result = cli("inspect", "-d", str(dest), str(clean_archive))
    assert result.returncode == 0
    assert not dest.exists()
    assert clean_archive.read_bytes() == before


def test_json_document_shape(cli: CliRunner, clean_archive: Path, dest: Path) -> None:
    document = _json(cli("inspect", "--json", "-d", str(dest), str(clean_archive)))
    assert document["archive"] == str(clean_archive)
    assert document["destination"] == str(dest)
    assert document["ok"] is True
    inspection = document["inspection"]
    assert inspection["total_entries"] == 3
    assert inspection["violations"] == []
    assert inspection["member_count_over_limit"] is False
    names = [member["member"] for member in inspection["members"]]
    assert names == ["readme.txt", "src/main.py", "data.csv"]
    member = inspection["members"][0]
    assert member["target"] == str(dest / "readme.txt")
    assert member["compressed_size"] == 5
    assert member["encrypted"] is False


def test_destination_defaults_to_the_current_directory(
    cli: CliRunner, clean_archive: Path, workdir: Path
) -> None:
    document = _json(cli("inspect", "--json", str(clean_archive), cwd=workdir))
    assert Path(document["destination"]).resolve() == workdir.resolve()


def test_works_without_reading_any_payload(cli: CliRunner, workdir: Path) -> None:
    """Corrupt data must not matter: only metadata is examined."""
    path = write_archive(workdir / "c.zip", [("a.txt", b"payload" * 100)])
    flip_byte(path, data_offset(path, "a.txt") + 3)
    assert cli("inspect", "-d", str(workdir / "d"), str(path)).returncode == 0


def test_encrypted_members_are_listed_without_a_password(
    cli: CliRunner, workdir: Path, dest: Path
) -> None:
    path = workdir / "e.zip"
    with ZipFile(path, "w", encryption=ziplet.WZ_AES) as zf:
        zf.setpassword(PASSWORD.encode())
        zf.writestr("secret.txt", b"s")
        zf.writestr("open.txt", b"o", encryption=None)
    result = cli("inspect", "-d", str(dest), str(path))
    assert result.returncode == 0, result
    assert "Encrypted members (1):\n    secret.txt" in result.stdout
    document = _json(cli("inspect", "--json", "-d", str(dest), str(path)))
    assert document["inspection"]["encrypted_members"] == ["secret.txt"]


# --- hostile archives -----------------------------------------------------------


def test_default_policy_flags_every_kind_of_hostile_member(
    cli: CliRunner, hostile_archive: Path, dest: Path
) -> None:
    result = cli("inspect", "--json", "-d", str(dest), str(hostile_archive))
    assert result.returncode == 1, result
    document = _json(result)
    assert document["ok"] is False
    codes = _codes(document)
    assert "parent_traversal" in codes["../escape.txt"]
    assert "absolute_path" in codes["/abs/path.txt"]
    assert "symlink" in codes["link"]
    assert "special_file" in codes["pipe"]
    assert "special_file" in codes["dev"]
    assert "duplicate_target" in codes["dup.txt"]
    assert "ok.txt" not in codes
    inspection = document["inspection"]
    assert inspection["duplicate_member_names"] == ["dup.txt"]
    assert inspection["symlinks"] == ["link"]
    assert sorted(inspection["special_files"]) == ["dev", "pipe"]
    assert "../escape.txt" in inspection["suspicious_paths"]


def test_human_report_lists_sections_and_violations(
    cli: CliRunner, hostile_archive: Path, dest: Path
) -> None:
    result = cli("inspect", "-d", str(dest), str(hostile_archive))
    assert result.returncode == 1
    text = result.stdout
    assert "\n  Violations (" in text
    assert "ERROR  ../escape.txt: parent traversal" in text
    assert "ERROR  link: " in text
    assert "ERROR  dup.txt: " in text
    # findings a violation already reports are not listed a second time
    for section in ("Suspicious paths", "Symlinks", "Special files", "Duplicate"):
        assert section not in text
    lines = text.splitlines()
    assert lines[4].startswith("Result:       FAILED (")
    assert lines[5:7] == ["", "Details:"]


def test_hostile_names_are_escaped_in_the_report(
    cli: CliRunner, workdir: Path, dest: Path
) -> None:
    name = "../evil\x1b[31mred\nline.txt"
    path = write_archive(workdir / "h.zip", [(name, b"x")])
    result = cli("inspect", "-d", str(dest), str(path))
    assert result.returncode == 1
    assert "\x1b" not in result.stdout
    assert "../evil\\x1b[31mred\\x0aline.txt" in result.stdout


def test_default_policy_matches_what_extraction_enforces(
    cli: CliRunner, workdir: Path, dest: Path
) -> None:
    """A zip-bomb-like ratio is an error by default, like in extractall."""
    path = write_archive(workdir / "b.zip", [("zeros.bin", b"\0" * 2_000_000)])
    with ZipFile(path) as zf:  # rewrite deflated so the ratio is huge
        pass
    bomb = workdir / "bomb.zip"
    with ZipFile(bomb, "w", compression=ziplet.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\0" * 2_000_000)
    result = cli("inspect", "--json", "-d", str(dest), str(bomb))
    assert result.returncode == 1
    assert "compression_ratio" in _codes(_json(result))["zeros.bin"]
    relaxed = cli(
        "inspect", "-d", str(dest), str(bomb),
        "--policy-json", '{"max_compression_ratio": null}',
    )  # fmt: skip
    assert relaxed.returncode == 0, relaxed


# --- policies -------------------------------------------------------------------


def _policy(
    workdir: Path, document: Mapping[str, JsonValue], name: str = "policy.json"
) -> Path:
    path = workdir / name
    path.write_text(json.dumps(document))
    return path


def test_policy_file_drives_the_verdict(
    cli: CliRunner, workdir: Path, dest: Path
) -> None:
    archive = write_archive(
        workdir / "a.zip", [("keep.txt", b"1"), ("drop.tar.gz", b"2"), ("x.exe", b"3")]
    )
    policy = _policy(workdir, {"blocked_extensions": [".tar.gz", ".exe"]})
    result = cli(
        "inspect", "--json", "--policy", str(policy), "-d", str(dest), str(archive)
    )
    assert result.returncode == 1
    codes = _codes(_json(result))
    assert codes == {
        "drop.tar.gz": {"extension_blocked"},
        "x.exe": {"extension_blocked"},
    }


def test_allowed_extensions_reject_everything_else(
    cli: CliRunner, workdir: Path, dest: Path
) -> None:
    archive = write_archive(
        workdir / "a.zip",
        [("a.txt", b"1"), ("b.md", b"2"), ("README", b"3"), ("c.py", b"4")],
    )  # fmt: skip
    result = cli(
        "inspect", "--json", "-d", str(dest), str(archive),
        "--policy-json", '{"allowed_extensions": [".txt", ""]}',
    )  # fmt: skip
    assert _codes(_json(result)) == {
        "b.md": {"extension_not_allowed"},
        "c.py": {"extension_not_allowed"},
    }


def test_entry_limit_is_reported_once_for_the_archive(
    cli: CliRunner, workdir: Path, dest: Path
) -> None:
    archive = write_archive(workdir / "a.zip", [(f"f{i}.txt", b"x") for i in range(5)])
    result = cli(
        "inspect", "--json", "-d", str(dest), str(archive),
        "--policy-json", '{"max_entries": 3}',
    )  # fmt: skip
    assert result.returncode == 1
    document = _json(result)
    assert _codes(document) == {"<archive>": {"max_entries"}}
    assert document["inspection"]["member_count_over_limit"] is True
    human = cli(
        "inspect", "-d", str(dest), str(archive), "--policy-json", '{"max_entries": 3}'
    )
    assert "archive contains 5 entries, limit is 3" in human.stdout


def test_only_error_level_violations_fail_the_run(
    cli: CliRunner, workdir: Path, dest: Path
) -> None:
    archive = write_archive(workdir / "a.zip", [("x.exe", b"1"), ("y.dll", b"2")])
    lenient = cli(
        "inspect", "--json", "-d", str(dest), str(archive),
        "--policy-json",
        '{"blocked_extensions": [".exe", ".dll"], "on_violation": "skip"}',
    )  # fmt: skip
    assert lenient.returncode == 0, lenient
    document = _json(lenient)
    assert document["ok"] is True
    assert {v["action"] for v in document["inspection"]["violations"]} == {"skip"}
    warn = cli(
        "inspect", "-d", str(dest), str(archive),
        "--policy-json", '{"blocked_extensions": [".exe"], "on_violation": "warn"}',
    )  # fmt: skip
    assert warn.returncode == 0
    assert "WARN   x.exe: extension is blocked" in warn.stdout
    assert warn.stdout.splitlines()[4] == "Result:       OK"


def test_a_rule_can_override_the_default_action_for_one_field(
    cli: CliRunner, workdir: Path, dest: Path
) -> None:
    archive = write_archive(workdir / "a.zip", [("x.exe", b"1"), ("y.txt", b"2")])
    policy = _policy(
        workdir,
        {
            "on_violation": "skip",
            "blocked_extensions": {"value": [".exe"], "on_violation": "error"},
        },
    )
    result = cli("inspect", "--policy", str(policy), "-d", str(dest), str(archive))
    assert result.returncode == 1
    assert "ERROR  x.exe: extension is blocked" in result.stdout


def test_inline_policy_layers_over_the_policy_file(
    cli: CliRunner, workdir: Path, dest: Path
) -> None:
    archive = write_archive(workdir / "a.zip", [(f"f{i}.txt", b"x") for i in range(5)])
    strict = _policy(workdir, {"max_entries": 1, "max_member_size": 10})
    only_file = cli("inspect", "--policy", str(strict), "-d", str(dest), str(archive))
    assert only_file.returncode == 1
    layered = cli(
        "inspect", "--policy", str(strict), "--policy-json", '{"max_entries": 100}',
        "-d", str(dest), str(archive),
    )  # fmt: skip
    assert layered.returncode == 0, layered


def test_policy_from_standard_input(cli: CliRunner, workdir: Path, dest: Path) -> None:
    archive = write_archive(workdir / "a.zip", [("x.exe", b"1")])
    result = cli(
        "inspect", "--policy", "-", "-d", str(dest), str(archive),
        stdin='{"blocked_extensions": [".exe"]}',
    )  # fmt: skip
    assert result.returncode == 1
    assert "x.exe: extension is blocked" in result.stdout


def test_destination_is_used_to_detect_overwrites(
    cli: CliRunner, clean_archive: Path, dest: Path
) -> None:
    dest.mkdir()
    (dest / "readme.txt").write_text("already here")
    result = cli("inspect", "--json", "-d", str(dest), str(clean_archive))
    assert result.returncode == 1
    assert _codes(_json(result)) == {"readme.txt": {"overwrite"}}
    allow = cli(
        "inspect", "-d", str(dest), str(clean_archive),
        "--policy-json", '{"allow_overwrite": true, "overwrite_policy": "replace"}',
    )  # fmt: skip
    assert allow.returncode == 0, allow


def test_destination_root_in_the_policy_confines_targets(
    cli: CliRunner, clean_archive: Path, workdir: Path
) -> None:
    result = cli(
        "inspect", "--json", "-d", str(workdir / "elsewhere"), str(clean_archive),
        "--policy-json", json.dumps({"destination_root": str(workdir / "root")}),
    )  # fmt: skip
    assert result.returncode == 1
    assert {"outside_root"} <= set().union(*_codes(_json(result)).values())


# --- bad input ------------------------------------------------------------------


def test_invalid_policy_lists_every_problem_and_exits_2(
    cli: CliRunner, clean_archive: Path
) -> None:
    result = cli(
        "inspect", str(clean_archive), "--policy-json",
        '{"max_entires": 5, "on_violation": "ignore",'
        ' "blocked_extensions": [".tar.gz", "exe"]}',
    )  # fmt: skip
    assert result.returncode == 2, result
    assert result.stdout == ""
    assert "ziplet: error: invalid policy (--policy-json)" in result.stderr
    assert "max_entires: unknown field; did you mean 'max_entries'?" in result.stderr
    assert "on_violation: expected one of" in result.stderr
    assert "blocked_extensions[1]: expected an extension" in result.stderr
    assert "Traceback" not in result.stderr


def test_invalid_policy_file_names_the_file(
    cli: CliRunner, clean_archive: Path, workdir: Path
) -> None:
    policy = _policy(workdir, {"max_entries": "many"})
    result = cli("inspect", "--policy", str(policy), str(clean_archive))
    assert result.returncode == 2
    assert f"invalid policy (--policy {policy})" in result.stderr


def test_missing_policy_file_is_a_usage_error(
    cli: CliRunner, clean_archive: Path, workdir: Path
) -> None:
    result = cli("inspect", "--policy", str(workdir / "nope.json"), str(clean_archive))
    assert result.returncode == 2
    assert "cannot read policy file" in result.stderr


def test_policy_errors_are_reported_before_the_archive_is_opened(
    cli: CliRunner, workdir: Path
) -> None:
    result = cli("inspect", str(workdir / "missing.zip"), "--policy-json", "{")
    assert result.returncode == 2
    assert "invalid policy" in result.stderr


def test_bad_archives_fail_cleanly(cli: CliRunner, workdir: Path) -> None:
    missing = cli("inspect", str(workdir / "missing.zip"))
    assert missing.returncode == 1
    assert "cannot open" in missing.stderr
    junk = workdir / "junk.zip"
    junk.write_bytes(b"nope")
    bad = cli("inspect", str(junk))
    assert bad.returncode == 1
    assert "not a valid ZIP archive" in bad.stderr


def test_directory_count_wording(cli: CliRunner, workdir: Path, dest: Path) -> None:
    def members_line(path: Path) -> str:
        out = cli("inspect", "-d", str(dest), str(path)).stdout
        return next(line for line in out.splitlines() if line.startswith("Members:"))

    path = workdir / "d.zip"
    with ZipFile(path, "w") as zf:
        zf.mkdir("one")
        zf.writestr("one/a.txt", b"x")
    assert members_line(path) == "Members:      2 (1 directory)"
    with ZipFile(path, "w") as zf:
        zf.mkdir("one")
        zf.mkdir("two")
    assert members_line(path) == "Members:      2 (2 directories)"


def test_quiet_prints_nothing_for_a_clean_archive(
    cli: CliRunner, clean_archive: Path, dest: Path
) -> None:
    result = cli("inspect", "-q", str(clean_archive), "-d", str(dest))
    assert result.returncode == 0, result
    assert result.stdout == ""


def test_quiet_prints_only_the_violations(
    cli: CliRunner, hostile_archive: Path, dest: Path
) -> None:
    result = cli("inspect", "-q", str(hostile_archive), "-d", str(dest))
    assert result.returncode == 1, result
    lines = result.stdout.splitlines()
    assert lines[0] == "Details:"
    assert lines[1].startswith("  Violations (")
    assert "Result:" not in result.stdout
    assert not any(line.startswith(("Archive:", "Members:")) for line in lines)


def test_a_single_error_is_not_pluralised(
    cli: CliRunner, clean_archive: Path, dest: Path
) -> None:
    dest.mkdir()
    result = cli(
        "inspect", "-d", str(dest), str(clean_archive),
        "--policy-json", '{"max_entries": 2}',
    )  # fmt: skip
    assert result.returncode == 1, result
    assert "Result:       FAILED (1 error)" in result.stdout
    quiet = cli(
        "inspect", "-q", "-d", str(dest), str(clean_archive),
        "--policy-json", '{"max_entries": 2}',
    )  # fmt: skip
    assert quiet.stdout.splitlines()[1] == "  Violations (1):"


def test_findings_no_violation_reports_still_get_a_section(
    cli: CliRunner, hostile_archive: Path, dest: Path
) -> None:
    result = cli(
        "inspect", "-d", str(dest), str(hostile_archive),
        "--policy-json", '{"allow_symlinks": true}',
    )  # fmt: skip
    assert "\n  Symlinks (1):\n    link\n" in result.stdout


def test_the_destination_is_shown_with_or_without_the_option(
    cli: CliRunner, clean_archive: Path, dest: Path
) -> None:
    assert "Destination:" in cli("inspect", "-d", str(dest), str(clean_archive)).stdout
    assert "Destination:" in cli("inspect", str(clean_archive)).stdout
