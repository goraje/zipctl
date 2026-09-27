"""The ziplet CLI and 7-Zip: 7-Zip must accept and read what the CLI writes.

Skipped when 7-Zip (``7z`` or ``7zz``) is not on PATH; the Windows CI job selects
these with ``-m windows``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.functional.cli.conftest import CliRunner

SZ_EXE = shutil.which("7z") or shutil.which("7zz")

pytestmark = [
    pytest.mark.windows,
    pytest.mark.skipif(
        SZ_EXE is None,
        reason="7-Zip (7z or 7zz) not found in PATH; required for interop tests",
    ),
]

SECRET = "Cefzuj-hetveg-xifve5"
OTHER = "Zorvik-lantem-quaj8"
FILES = {
    "notes.txt": b"the quick brown fox " * 400,
    "docs/readme.txt": b"hello from the ziplet command line\n" * 50,
    "docs/empty.txt": b"",
}


def sz(*args: str) -> subprocess.CompletedProcess[str]:
    assert SZ_EXE is not None
    return subprocess.run([SZ_EXE, *args], capture_output=True, text=True)


def sz_methods(archive: Path, password: str | None = None) -> dict[str, str]:
    """File name -> ``Method`` as 7-Zip reports it (``AES-256 Deflate`` ...)."""
    args = ["l", "-slt", *([f"-p{password}"] if password else []), str(archive)]
    blocks = sz(*args).stdout.split("\n\n")
    methods: dict[str, str] = {}
    for block in blocks:
        fields = dict(
            line.split(" = ", 1) for line in block.splitlines() if " = " in line
        )
        if fields.get("Folder") == "-":  # files only; directories are always stored
            methods[Path(fields["Path"]).as_posix()] = fields["Method"]  # Windows: \
    return methods


def sz_reads(archive: Path, member: str, password: str | None = None) -> bytes:
    """The bytes 7-Zip extracts for *member* (fails the test if it cannot)."""
    args = ["e", "-so", "-y", *([f"-p{password}"] if password else [])]
    completed = subprocess.run(
        [str(SZ_EXE), *args, str(archive), member], capture_output=True
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return completed.stdout


def sz_accepts(archive: Path, password: str | None = None) -> bool:
    args = ["t", *([f"-p{password}"] if password else []), str(archive)]
    return sz(*args).returncode == 0


@pytest.fixture
def tree(workdir: Path) -> Path:
    root = workdir / "tree"
    for name, data in FILES.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def create(
    cli: CliRunner, workdir: Path, tree: Path, *options: str, **env: str
) -> Path:
    result = cli(
        "create",
        str(workdir / "out.zip"),
        "-C",
        str(tree),
        ".",
        *options,
        env={"ZIPLET_PASSWORD": SECRET, **env},
        cwd=workdir,
    )
    assert result.returncode == 0, result
    return workdir / "out.zip"


def assert_reads_everything(archive: Path, password: str | None) -> None:
    for name, data in FILES.items():
        assert sz_reads(archive, name, password) == data


# --- CLI writes, 7-Zip reads


@pytest.mark.parametrize(
    ("method", "label"),
    [("aes128", "AES-128"), ("aes192", "AES-192"), ("aes256", "AES-256")],
)
def test_7zip_reads_a_create_archive_protected_with_aes(
    cli: CliRunner, workdir: Path, tree: Path, method: str, label: str
) -> None:
    archive = create(cli, workdir, tree, "--encryption", method)
    assert sz_accepts(archive, SECRET)
    assert not sz_accepts(archive, OTHER)
    assert {m.split()[0] for m in sz_methods(archive, SECRET).values()} == {label}
    assert_reads_everything(archive, SECRET)


@pytest.mark.parametrize("version", ["1", "2"])
def test_7zip_reads_both_winzip_aes_versions(
    cli: CliRunner, workdir: Path, tree: Path, version: str
) -> None:
    archive = create(
        cli, workdir, tree, "--encryption", "aes256", "--wz-aes-version", version
    )
    assert_reads_everything(archive, SECRET)


def test_7zip_reads_a_create_archive_protected_with_zipcrypto(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    archive = create(cli, workdir, tree, "--encryption", "zipcrypto")
    assert sz_accepts(archive, SECRET)
    assert {m.split()[0] for m in sz_methods(archive).values()} == {"ZipCrypto"}
    assert_reads_everything(archive, SECRET)


@pytest.mark.parametrize("method", ["store", "deflate", "bzip2", "lzma"])
def test_7zip_reads_encrypted_members_under_every_compression(
    cli: CliRunner, workdir: Path, tree: Path, method: str
) -> None:
    archive = create(
        cli, workdir, tree, "--encryption", "aes256", "--compression", method
    )
    assert sz_accepts(archive, SECRET)
    assert_reads_everything(archive, SECRET)


def test_7zip_reads_per_file_protection_from_a_spec(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    spec = workdir / "spec.json"
    spec.write_text(
        json.dumps(
            {
                "version": 1,
                "default": {"method": "aes256", "password": {"env": "DEFAULT_PASS"}},
                "rules": [
                    {
                        "match": "docs/readme.txt",
                        "method": "aes128",
                        "password": {"env": "DOCS_PASS"},
                    },
                    {"match": "docs/empty.txt", "method": "none"},
                ],
            }
        )
    )
    archive = create(
        cli,
        workdir,
        tree,
        "--encryption-spec",
        str(spec),
        DEFAULT_PASS=SECRET,
        DOCS_PASS=OTHER,
    )
    labels = {n: m.split()[0] for n, m in sz_methods(archive, SECRET).items()}
    assert labels == {
        "notes.txt": "AES-256",
        "docs/readme.txt": "AES-128",
        "docs/empty.txt": "Deflate",  # not protected
    }
    assert sz_reads(archive, "notes.txt", SECRET) == FILES["notes.txt"]
    assert sz_reads(archive, "docs/readme.txt", OTHER) == FILES["docs/readme.txt"]
    assert sz_reads(archive, "docs/empty.txt") == b""
    assert not sz_accepts(archive, SECRET)  # one member needs the other password


# --- encrypt / decrypt / rewrite write, 7-Zip reads


def test_7zip_reads_what_encrypt_writes(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    plain = create(cli, workdir, tree)
    out = workdir / "encrypted.zip"
    result = cli(
        "encrypt",
        str(plain),
        str(out),
        "--encryption",
        "aes256",
        env={"ZIPLET_PASSWORD": OTHER},
        cwd=workdir,
    )
    assert result.returncode == 0, result
    assert sz_accepts(out, OTHER)
    assert_reads_everything(out, OTHER)


def test_7zip_reads_what_rewrite_writes_from_aes_to_zipcrypto(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    source = create(cli, workdir, tree, "--encryption", "aes256")
    out = workdir / "rewritten.zip"
    result = cli(
        "rewrite",
        str(source),
        str(out),
        "--encryption",
        "zipcrypto",
        env={"ZIPLET_OLD_PASSWORD": SECRET, "ZIPLET_PASSWORD": OTHER},
        cwd=workdir,
    )
    assert result.returncode == 0, result
    assert {m.split()[0] for m in sz_methods(out).values()} == {"ZipCrypto"}
    assert_reads_everything(out, OTHER)


def test_7zip_reads_what_decrypt_writes_without_a_password(
    cli: CliRunner, workdir: Path, tree: Path
) -> None:
    source = create(cli, workdir, tree, "--encryption", "aes192")
    out = workdir / "decrypted.zip"
    result = cli("decrypt", str(source), str(out), env={"ZIPLET_PASSWORD": SECRET})
    assert result.returncode == 0, result
    assert sz_accepts(out)
    assert_reads_everything(out, None)


# --- 7-Zip writes, the CLI reads and converts


@pytest.mark.parametrize("cipher", ["AES256", "ZipCrypto"])
def test_the_cli_decrypts_an_archive_made_by_7zip(
    cli: CliRunner, workdir: Path, tree: Path, cipher: str
) -> None:
    archive = workdir / "by7z.zip"
    # 7-Zip stores paths relative to where it runs, so run it inside the tree.
    made = subprocess.run(
        [str(SZ_EXE), "a", "-tzip", f"-mem={cipher}", f"-p{SECRET}", str(archive), "."],
        capture_output=True,
        text=True,
        cwd=tree,
    )
    assert made.returncode == 0, made.stdout + made.stderr
    plain = workdir / "plain.zip"
    result = cli("decrypt", str(archive), str(plain), env={"ZIPLET_PASSWORD": SECRET})
    assert result.returncode == 0, result
    assert sz_accepts(plain)
    for name, data in FILES.items():
        assert sz_reads(plain, name) == data
