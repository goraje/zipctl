"""``method_of``: how a member's protection is named."""

from __future__ import annotations

import io

import ziplet
from ziplet.cli.methods import ENCRYPTION_METHODS, NO_ENCRYPTION, method_of
from ziplet.zipfile.info import ZipInfo


def _protected(method: str) -> ZipInfo:
    chosen = ENCRYPTION_METHODS[method]
    buffer = io.BytesIO()
    with ziplet.ZipFile(buffer, "w") as zf:
        zf.writestr(
            "a.txt",
            b"data",
            encryption=chosen.scheme,
            password=b"pw" if chosen.is_encrypted else None,
            extra=ziplet.ZipFileExtra(wz_aes_nbits=chosen.aes_bits)
            if chosen.is_aes
            else None,
        )
    with ziplet.ZipFile(buffer) as zf:
        return zf.infolist()[0]


def test_method_of_names_every_method_it_can_write() -> None:
    for name, method in ENCRYPTION_METHODS.items():
        assert method_of(_protected(name)) is method, name


def test_plain_members_have_no_encryption() -> None:
    assert method_of(_protected("none")) is NO_ENCRYPTION
    assert not NO_ENCRYPTION.is_encrypted
