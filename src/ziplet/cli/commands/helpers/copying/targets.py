"""How each member of a copy is written, and the record of what was written."""

from __future__ import annotations

from dataclasses import dataclass

from ziplet.cli.errors import CliError
from ziplet.cli.methods import (
    NO_ENCRYPTION,
    UNKNOWN_AES,
    EncryptionMethod,
    extra_for,
    method_of,
)
from ziplet.cli.output import printable
from ziplet.zipfile.file import ZipFileExtra
from ziplet.zipfile.info import ZipInfo


@dataclass(frozen=True)
class Target:
    """How one member is written: its encryption method, password and AES settings."""

    method: EncryptionMethod = NO_ENCRYPTION
    password: bytes | None = None
    extra: ZipFileExtra | None = None


PLAIN = Target()


def target_for_method(
    method: EncryptionMethod, password: bytes | None, aes_version: int | None
) -> Target:
    """The target that writes with *method*, its *password* and AES version."""
    return Target(
        method,
        password if method.is_encrypted else None,
        extra_for(method, aes_version),
    )


def keep_target(info: ZipInfo, password: bytes | None) -> Target:
    """The target that writes *info* again with the protection it already has."""
    method = method_of(info)
    if not method.is_encrypted:
        return PLAIN
    if method is UNKNOWN_AES:
        raise CliError(
            f"cannot keep the encryption of {printable(info.filename)}: unknown "
            f"AES strength {info.aes_extra.wz_aes_strength}"
        )
    if not method.is_aes:
        return Target(method, password)
    extra = ZipFileExtra(
        force_wz_aes_version=info.aes_extra.wz_aes_version, wz_aes_nbits=method.aes_bits
    )
    return Target(method, password, extra)


@dataclass
class Copied:
    """What was written for one member."""

    name: str
    directory: bool
    size: int
    crc: int
    compression: str | None
    before: EncryptionMethod
    after: EncryptionMethod
    raw: bool = False  # the compressed data was copied as it is


def describe_failure(exc: Exception) -> str:
    return printable(str(exc) or type(exc).__name__)
