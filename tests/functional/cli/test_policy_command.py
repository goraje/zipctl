"""``ziplet policy show`` and ``ziplet policy validate``."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from tests.functional.cli.conftest import CliRunner
from tests.functional.cli.support import write_archive
from ziplet import ExtractPolicy, policy_from_json, policy_to_json

README = Path(__file__).resolve().parents[3] / "README.md"


def _write(workdir: Path, text: str | bytes, name: str = "p.json") -> Path:
    path = workdir / name
    path.write_bytes(text if isinstance(text, bytes) else text.encode())
    return path


# --- policy show -------------------------------------------------------------------


def test_show_prints_the_default_policy_as_json(cli: CliRunner) -> None:
    result = cli("policy", "show")
    assert result.returncode == 0, result
    assert result.stdout == policy_to_json(ExtractPolicy()) + "\n"
    assert json.loads(result.stdout)["version"] == 1


def test_show_applies_the_file_then_the_inline_document(
    cli: CliRunner, workdir: Path
) -> None:
    path = _write(workdir, '{"max_entries": 7, "max_member_size": 100}')
    result = cli(
        "policy", "show", "--policy", str(path), "--policy-json", '{"max_entries": 9}'
    )
    assert result.returncode == 0, result
    policy = policy_from_json(result.stdout)
    assert policy.max_entries == 9
    assert policy.max_member_size == 100
    assert policy.on_violation == ExtractPolicy().on_violation


def test_show_output_is_a_fixed_point(cli: CliRunner, workdir: Path) -> None:
    """What ``show`` prints, ``show --policy -`` prints back unchanged."""
    first = cli(
        "policy", "show", "--policy-json",
        '{"blocked_extensions": {"value": [".exe", ".tar.gz"], "on_violation": "skip"},'
        ' "max_entries": null, "overwrite_policy": "rename"}',
    )  # fmt: skip
    again = cli("policy", "show", "--policy", "-", stdin=first.stdout)
    assert again.returncode == 0, again
    assert again.stdout == first.stdout


def test_show_normalises_extensions(cli: CliRunner) -> None:
    result = cli(
        "policy", "show", "--policy-json", '{"allowed_extensions": [".TXT", ".Md"]}'
    )
    assert json.loads(result.stdout)["allowed_extensions"] == [".md", ".txt"]


def test_show_rejects_an_invalid_policy(cli: CliRunner) -> None:
    result = cli("policy", "show", "--policy-json", '{"nonsense": 1}')
    assert result.returncode == 2
    assert result.stdout == ""
    assert "invalid policy (--policy-json)" in result.stderr


def test_show_can_read_the_policy_file_with_a_byte_order_mark(
    cli: CliRunner, workdir: Path
) -> None:
    path = _write(workdir, b'\xef\xbb\xbf{"max_entries": 3}')
    assert (
        policy_from_json(
            cli("policy", "show", "--policy", str(path)).stdout
        ).max_entries
        == 3
    )


# --- policy validate ---------------------------------------------------------------


def test_validate_accepts_a_good_file(cli: CliRunner, workdir: Path) -> None:
    path = _write(workdir, '{"version": 1, "max_entries": 5}')
    result = cli("policy", "validate", str(path))
    assert result.returncode == 0, result
    assert result.stdout == f"OK      {path}\n\nChecked 1 policy file: all OK\n"


def test_validate_reports_every_problem_with_its_path(
    cli: CliRunner, workdir: Path
) -> None:
    path = _write(
        workdir,
        '{"max_entires": 5, "max_member_size": {"value": "big"}, "version": 3,'
        ' "blocked_extensions": ["exe"]}',
    )
    result = cli("policy", "validate", str(path))
    assert result.returncode == 2, result
    lines = result.stdout.splitlines()
    assert lines[0] == f"FAILED  {path}: 4 issues"
    body = "\n".join(lines[1:])
    assert "max_entires: unknown field; did you mean 'max_entries'?" in body
    assert "max_member_size.value: expected integer or null, got string" in body
    assert "version: unsupported policy format version 3" in body
    assert "blocked_extensions[0]: expected an extension" in body
    assert lines[-1] == "Checked 1 policy file: 1 failed"
    assert len(lines) == 7


def test_validate_checks_every_file_and_fails_if_any_is_invalid(
    cli: CliRunner, workdir: Path
) -> None:
    good = _write(workdir, "{}", "good.json")
    bad = _write(workdir, "[]", "bad.json")
    also_good = _write(workdir, '{"fsync_files": false}', "good2.json")
    result = cli("policy", "validate", str(good), str(bad), str(also_good))
    assert result.returncode == 2
    assert f"OK      {good}" in result.stdout
    assert f"FAILED  {bad}: 1 issue" in result.stdout
    assert f"OK      {also_good}" in result.stdout
    assert "<policy>: expected an object, got list" in result.stdout
    assert result.stdout.endswith("\nChecked 3 policy files: 1 failed\n")


def test_validate_reads_standard_input(cli: CliRunner) -> None:
    ok = cli("policy", "validate", "-", stdin='{"max_entries": 1}')
    assert ok.returncode == 0
    assert ok.stdout == "OK      -\n\nChecked 1 policy file: all OK\n"
    bad = cli("policy", "validate", "-", stdin="{not json")
    assert bad.returncode == 2
    assert "invalid JSON" in bad.stdout


def test_validate_refuses_standard_input_twice(cli: CliRunner) -> None:
    result = cli("policy", "validate", "-", "-", stdin="{}")
    assert result.returncode == 2
    assert "standard input can only be given once" in result.stderr


@pytest.mark.parametrize(
    ("content", "fragment"),
    [
        ("", "invalid JSON"),
        ("   \n", "invalid JSON"),
        ("{", "invalid JSON"),
        ('{"max_entries": NaN}', "NaN is not allowed"),
        ('{"max_compression_ratio": Infinity}', "Infinity is not allowed"),
        ('{"max_entries": 1, "max_entries": 2}', "duplicate key"),
        ('"just a string"', "expected an object, got string"),
        ("null", "expected an object, got null"),
    ],
)
def test_validate_explains_malformed_documents(
    cli: CliRunner, workdir: Path, content: str, fragment: str
) -> None:
    path = _write(workdir, content)
    result = cli("policy", "validate", str(path))
    assert result.returncode == 2, result
    assert fragment in result.stdout
    assert "Traceback" not in result.stderr


def test_validate_json_output(cli: CliRunner, workdir: Path) -> None:
    good = _write(workdir, "{}", "good.json")
    bad = _write(workdir, '{"oops": 1}', "bad.json")
    result = cli("policy", "validate", "--json", str(good), str(bad))
    assert result.returncode == 2
    document = json.loads(result.stdout)
    assert document["ok"] is False
    by_file = {entry["file"]: entry for entry in document["files"]}
    assert by_file[str(good)] == {"file": str(good), "valid": True, "issues": []}
    (issue,) = by_file[str(bad)]["issues"]
    assert issue["path"] == "oops"
    assert issue["message"].startswith("unknown field")


def test_validate_json_output_for_valid_files_exits_zero(
    cli: CliRunner, workdir: Path
) -> None:
    good = _write(workdir, "{}")
    result = cli("policy", "validate", "--json", str(good))
    assert result.returncode == 0
    assert json.loads(result.stdout)["ok"] is True


def test_validate_problems_with_the_file_itself(cli: CliRunner, workdir: Path) -> None:
    missing = cli("policy", "validate", str(workdir / "nope.json"))
    assert missing.returncode == 2
    assert "cannot read policy file" in missing.stdout
    directory = cli("policy", "validate", str(workdir))
    assert directory.returncode == 2
    assert "cannot read policy file" in directory.stdout
    not_utf8 = _write(workdir, b"\xff\xfe\x00{}", "latin.json")
    result = cli("policy", "validate", str(not_utf8))
    assert result.returncode == 2
    assert "not valid UTF-8" in result.stdout


def test_validate_goes_on_after_an_unreadable_file(
    cli: CliRunner, workdir: Path
) -> None:
    good = _write(workdir, b"{}", "good.json")
    result = cli("policy", "validate", str(workdir / "nope.json"), str(good), "--json")
    assert result.returncode == 2, result
    report = json.loads(result.stdout)
    assert [f["valid"] for f in report["files"]] == [False, True]
    assert "cannot read policy file" in report["files"][0]["issues"][0]["message"]


def test_hostile_file_names_are_escaped(cli: CliRunner, workdir: Path) -> None:
    result = cli("policy", "validate", str(workdir / "bad\x1b[31mname.json"))
    assert result.returncode == 2
    assert "\x1b" not in result.stderr


# --- the documentation stays true -----------------------------------------------


def _readme_json_blocks() -> list[str]:
    text = README.read_text(encoding="utf-8")
    blocks = re.findall(r"```json\n(.*?)```", text, flags=re.DOTALL)
    return [
        block for block in blocks if '"version"' in block and '"match"' not in block
    ]


def test_the_readme_has_a_policy_example() -> None:
    assert _readme_json_blocks()


@pytest.mark.parametrize("block", _readme_json_blocks())
def test_every_policy_example_in_the_readme_validates(
    cli: CliRunner, block: str
) -> None:
    result = cli("policy", "validate", "-", stdin=block)
    assert result.returncode == 0, result


# --- ZIPLET_POLICY -----------------------------------------------------------------


def test_the_environment_policy_sits_between_the_defaults_and_the_options(
    cli: CliRunner, workdir: Path
) -> None:
    base = _write(workdir, '{"max_entries": 7, "max_member_size": 100}', "env.json")
    own = _write(workdir, '{"max_entries": 8}', "own.json")
    env = {"ZIPLET_POLICY": str(base)}

    alone = policy_from_json(cli("policy", "show", env=env).stdout)
    assert (alone.max_entries, alone.max_member_size) == (7, 100)

    with_file = policy_from_json(
        cli("policy", "show", "--policy", str(own), env=env).stdout
    )
    assert (with_file.max_entries, with_file.max_member_size) == (8, 100)

    inline = policy_from_json(
        cli("policy", "show", "--policy-json", '{"max_entries": 9}', env=env).stdout
    )
    assert (inline.max_entries, inline.max_member_size) == (9, 100)


def test_the_environment_policy_applies_to_extraction_and_inspection(
    cli: CliRunner, workdir: Path
) -> None:
    archive = write_archive(workdir / "a.zip", [("a.txt", b"1"), ("b.txt", b"2")])
    strict = _write(workdir, '{"max_entries": 1}', "strict.json")
    env = {"ZIPLET_POLICY": str(strict)}
    assert cli("inspect", str(archive), env=env).returncode == 1
    assert (
        cli("extract", str(archive), "-d", str(workdir / "out"), env=env).returncode
        == 1
    )
    plain = cli(
        "extract", str(archive), "--no-policy", "-d", str(workdir / "out2"), env=env
    )
    assert plain.returncode == 0, plain


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("missing.json", "missing.json"),
        ("-", "must name a file"),
    ],
)
def test_an_unusable_environment_policy_is_refused(
    cli: CliRunner, workdir: Path, value: str, message: str
) -> None:
    result = cli("policy", "show", env={"ZIPLET_POLICY": value}, cwd=workdir)
    assert result.returncode == 2, result
    assert message in result.stderr


def test_an_invalid_environment_policy_names_its_origin(
    cli: CliRunner, workdir: Path
) -> None:
    bad = _write(workdir, '{"max_entries": "many"}', "bad.json")
    result = cli("policy", "show", env={"ZIPLET_POLICY": str(bad)})
    assert result.returncode == 2, result
    assert f"invalid policy (ZIPLET_POLICY={bad})" in result.stderr


def test_standard_input_that_is_not_utf8_is_a_usage_error(cli: CliRunner) -> None:
    validated = cli("policy", "validate", "-", stdin=b"\xff\xfe{")
    assert validated.returncode == 2, validated
    assert "FAILED  -: 1 issue" in validated.stdout
    assert "not valid UTF-8" in validated.stdout
    shown = cli("policy", "show", "--policy", "-", stdin=b"\xff")
    assert shown.returncode == 2, shown
    assert "not valid UTF-8" in shown.stderr
    assert "unexpected" not in shown.stderr


def test_a_policy_on_standard_input_may_start_with_a_byte_order_mark(
    cli: CliRunner,
) -> None:
    result = cli("policy", "validate", "-", stdin=b'\xef\xbb\xbf{"max_entries": 1}')
    assert result.returncode == 0, result
