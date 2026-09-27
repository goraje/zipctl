"""Archives and comparisons shared by the encrypt/decrypt/rewrite tests."""

from __future__ import annotations

import random
import struct
from pathlib import Path
from typing import NamedTuple

import ziplet
from ziplet import ZipFile
from ziplet.zipfile.info import ZipInfo

PASSWORD = "correct horse battery"
PW = PASSWORD.encode()
OTHER = "staple"
OTHER_PW = OTHER.encode()
ARCHIVE_COMMENT = b"the archive comment"
_RANDOM = random.Random(1234)

# name, method, data: a mix of compression methods, modes, dates and comments
FILES: list[tuple[str, int, bytes]] = [
    ("docs/readme.txt", ziplet.ZIP_DEFLATED, b"read me\n" * 40),
    (
        "docs/data.bin",
        ziplet.ZIP_BZIP2,
        bytes(_RANDOM.randrange(256) for _ in range(5000)),
    ),
    ("notes/ünïcode ✓.txt", ziplet.ZIP_LZMA, "grüße".encode() * 30),
    ("empty.txt", ziplet.ZIP_STORED, b""),
    ("run.sh", ziplet.ZIP_STORED, b"#!/bin/sh\necho hi\n"),
    ("link", ziplet.ZIP_STORED, b"docs/readme.txt"),
]
_MODES = {"run.sh": 0o100755, "link": 0o120777}
DIRECTORIES = ["docs/", "notes/"]


def extra_fields(index: int) -> bytes:
    """An extended timestamp (UT) and Unix owner (ux) field, different per member."""
    stamp = struct.pack("<HHBI", 0x5455, 5, 1, 1_600_000_000 + index)
    owner = struct.pack("<HHBBIBI", 0x7875, 11, 1, 4, 1000 + index, 4, 100 + index)
    return stamp + owner


def _info(name: str, method: int, index: int) -> ZipInfo:
    info = ZipInfo(name, (2001 + index, 1 + index, 2 + index, 3, 4, 2 * index))
    info.compress_type = method
    info.external_attr = (_MODES.get(name, 0o100640)) << 16
    info.comment = f"comment {index}".encode()
    info.extra = extra_fields(index)
    if name == "docs/readme.txt":
        info.internal_attr = 1  # "probably text"
    if name == "empty.txt":
        info.create_system = 0  # made on FAT, not Unix
    return info


def make_source(
    path: Path,
    *,
    encryption: str | None = None,
    password: bytes | None = None,
    extra: ziplet.ZipFileExtra | None = None,
) -> Path:
    """Write the sample archive, every file protected the same way."""
    with ZipFile(path, "w") as zf:
        zf.comment = ARCHIVE_COMMENT
        for name in DIRECTORIES:
            info = ZipInfo(name, (2020, 6, 7, 8, 9, 10))
            info.external_attr = (0o40750 << 16) | 0x10
            info.comment = b"a folder"
            info.extra = extra_fields(len(DIRECTORIES))
            zf.mkdir(info)
        for index, (name, method, data) in enumerate(FILES):
            zf.writestr(
                _info(name, method, index),
                data,
                encryption=encryption,
                password=password,
                extra=extra,
            )
    return path


def make_mixed(path: Path) -> Path:
    """Four members: two passwords, three schemes, one plain."""
    aes = ziplet.WZ_AES
    with ZipFile(path, "w") as zf:
        zf.writestr(
            "a.txt", b"alpha", encryption=aes, password=PW,
            extra=ziplet.ZipFileExtra(wz_aes_nbits=256),
        )  # fmt: skip
        zf.writestr(
            "b.txt", b"bravo", encryption=aes, password=OTHER_PW,
            extra=ziplet.ZipFileExtra(wz_aes_nbits=192, force_wz_aes_version=1),
        )  # fmt: skip
        zf.writestr("c.txt", b"charlie")
        zf.writestr("d.txt", b"delta", encryption=ziplet.ZIP_CRYPTO, password=PW)
    return path


class Row(NamedTuple):
    """What :func:`snapshot` records of one member."""

    date_time: tuple[int, int, int, int, int, int]
    external_attr: int
    comment: bytes
    compress_type: int
    is_dir: bool
    data: bytes
    internal_attr: int
    create_system: int
    carried_extra: bytes


def snapshot(
    path: Path, passwords: dict[str, bytes] | bytes | None = None
) -> dict[str, Row]:
    """Everything a copy must preserve, plus the decrypted data, per member."""
    with ZipFile(path) as zf:
        rows: dict[str, Row] = {}
        for info in zf.infolist():
            if isinstance(passwords, dict):
                pwd = passwords.get(info.filename)
            else:
                pwd = passwords
            data = (
                b""
                if info.is_dir()
                else zf.read(info, pwd=pwd if info.is_encrypted else None)
            )
            rows[info.filename] = Row(
                info.date_time,
                info.external_attr,
                info.comment,
                info.compress_type,
                info.is_dir(),
                data,
                info.internal_attr,
                info.create_system,
                info.carried_extra,
            )
        return rows


def schemes(path: Path) -> dict[str, str]:
    """Per member: none, zipcrypto, or aes128/192/256 (with ``-v1`` for AES-1)."""
    out: dict[str, str] = {}
    with ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if not info.is_encrypted:
                out[info.filename] = "none"
            elif info.aes_extra.wz_aes_strength is None:
                out[info.filename] = "zipcrypto"
            else:
                bits = {1: 128, 2: 192, 3: 256}[info.aes_extra.wz_aes_strength]
                v1 = "-v1" if info.aes_extra.wz_aes_version == 1 else ""
                out[info.filename] = f"aes{bits}{v1}"
    return out


def leftovers(directory: Path) -> list[str]:
    """Scratch files a run should never leave behind."""
    return sorted(p.name for p in directory.glob(".ziplet-*"))
