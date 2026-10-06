"""The compression and encryption methods the CLI knows, in one place."""

from __future__ import annotations

import argparse
from dataclasses import dataclass

from zipctl.cli.errors import UsageError
from zipctl.compression import (
    ZIP_BZIP2,
    ZIP_DEFLATED,
    ZIP_LZMA,
    ZIP_STORED,
    ZIP_ZSTANDARD,
    compressor_names,
    registry,
)
from zipctl.cryptography import WZ_AES, ZIP_CRYPTO
from zipctl.zipfile.info import ZipInfo

__all__ = [
    "COMPRESSION",
    "ENCRYPTABLE",
    "ENCRYPTION_METHODS",
    "EncryptionMethod",
    "METHOD_CHOICES",
    "NO_ENCRYPTION",
    "compression_label",
    "method_of",
    "require_compression",
    "require_level",
]


@dataclass(frozen=True)
class EncryptionMethod:
    """One name a user can give for how a member is protected."""

    name: str
    scheme: str | None  # the ZipFile encryption scheme; None for plain
    aes_bits: int  # AES key size; 0 when the scheme is not AES
    label: str  # how listings and reports call it

    @property
    def is_aes(self) -> bool:
        return self.scheme == WZ_AES

    @property
    def is_encrypted(self) -> bool:
        return self.scheme is not None


ENCRYPTION_METHODS = {
    method.name: method
    for method in (
        EncryptionMethod("aes256", WZ_AES, 256, "AES-256"),
        EncryptionMethod("aes192", WZ_AES, 192, "AES-192"),
        EncryptionMethod("aes128", WZ_AES, 128, "AES-128"),
        EncryptionMethod("zipcrypto", ZIP_CRYPTO, 0, "ZipCrypto"),
        EncryptionMethod("none", None, 0, "none"),
    )
}
METHOD_CHOICES = ", ".join(ENCRYPTION_METHODS)  # for messages and help
ENCRYPTABLE = tuple(name for name in ENCRYPTION_METHODS if name != "none")
NO_ENCRYPTION = ENCRYPTION_METHODS["none"]

# Method names the CLI takes -> ZIP compression ids.
COMPRESSION = {
    compressor_names[compress_type]: compress_type
    for compress_type in (
        ZIP_STORED,
        ZIP_DEFLATED,
        ZIP_BZIP2,
        ZIP_LZMA,
        ZIP_ZSTANDARD,
    )
}


def method_of(info: ZipInfo) -> EncryptionMethod:
    """How the member described by *info* is protected in its archive."""
    scheme = info.encryption_scheme
    if scheme is None:
        return NO_ENCRYPTION
    if scheme == ZIP_CRYPTO:
        return ENCRYPTION_METHODS["zipcrypto"]
    return ENCRYPTION_METHODS[f"aes{info.aes_bits}"]


def require_compression(method: str) -> None:
    """Refuse a *method* (a key of :data:`COMPRESSION`) this install cannot run."""
    try:
        registry.check_compression(COMPRESSION[method])
    except (RuntimeError, NotImplementedError):
        extra = " (install zipctl[zstd])" if method == "zstd" else ""
        raise UsageError(
            f"compression method {method!r} is not available{extra}"
        ) from None


def require_level(method: str, level: int | None) -> None:
    """Refuse a *level* the compression *method* cannot use."""
    if level is None:
        return
    levels = registry.levels(COMPRESSION[method])
    if levels is None:
        raise UsageError(f"compression method {method!r} takes no --level")
    if level not in levels:
        raise UsageError(
            f"--level {level} is out of range for {method} "
            f"({levels[0]} to {levels[-1]})",
        )


def compression_label(info: ZipInfo) -> str:
    return compressor_names.get(info.compress_type, str(info.compress_type))


def add_compression_options(
    parser: argparse.ArgumentParser, *, default: str | None, default_text: str
) -> None:
    """Add ``-m/--compression METHOD`` and ``-L/--level N``."""
    parser.add_argument(
        "-m",
        "--compression",
        choices=list(COMPRESSION),
        default=default,
        metavar="METHOD",
        help=f"compression method: {', '.join(COMPRESSION)}. Default: {default_text}",
    )
    parser.add_argument(
        "-L", "--level", type=int, metavar="N", help="compression level"
    )
