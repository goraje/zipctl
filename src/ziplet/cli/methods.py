"""The compression and encryption methods the CLI knows, in one place."""

from __future__ import annotations

from dataclasses import dataclass

from ziplet.cli.errors import UsageError
from ziplet.compression import (
    ZIP_BZIP2,
    ZIP_DEFLATED,
    ZIP_LZMA,
    ZIP_STORED,
    ZIP_ZSTANDARD,
    compressor_names,
    registry,
)
from ziplet.cryptography import WZ_AES, ZIP_CRYPTO
from ziplet.zipfile.file import ZipFileExtra
from ziplet.zipfile.info import ZipInfo

__all__ = [
    "COMPRESSION",
    "ENCRYPTABLE",
    "ENCRYPTION_METHODS",
    "EncryptionMethod",
    "METHOD_CHOICES",
    "NO_ENCRYPTION",
    "UNKNOWN_AES",
    "compression_label",
    "extra_for",
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
# An AES strength this tool does not know; readable in a listing, never written.
UNKNOWN_AES = EncryptionMethod("aes", WZ_AES, 0, "AES")

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

# Compression levels each method accepts (the registry does not record them);
# store and lzma take none.
_LEVELS = {
    "deflate": range(10),
    "bzip2": range(1, 10),
    "zstd": range(-131072, 23),
}


def method_of(info: ZipInfo) -> EncryptionMethod:
    """How the member described by *info* is protected in its archive."""
    scheme = info.encryption_scheme
    if scheme is None:
        return NO_ENCRYPTION
    if scheme == ZIP_CRYPTO:
        return ENCRYPTION_METHODS["zipcrypto"]
    bits = info.aes_bits
    return ENCRYPTION_METHODS[f"aes{bits}"] if bits else UNKNOWN_AES


def extra_for(method: EncryptionMethod, aes_version: int | None) -> ZipFileExtra | None:
    """The per-entry AES settings for *method* (``None`` when it has none)."""
    if not method.is_aes:
        return None
    return ZipFileExtra(force_wz_aes_version=aes_version, wz_aes_nbits=method.aes_bits)


def require_compression(method: str) -> None:
    """Refuse a *method* (a key of :data:`COMPRESSION`) this install cannot run."""
    try:
        registry.check_compression(COMPRESSION[method])
    except (RuntimeError, NotImplementedError):
        extra = " (install ziplet[zstd])" if method == "zstd" else ""
        raise UsageError(
            f"compression method {method!r} is not available{extra}"
        ) from None


def require_level(method: str, level: int | None) -> None:
    """Refuse a *level* the compression *method* cannot use."""
    if level is None:
        return
    levels = _LEVELS.get(method)
    if levels is None:
        raise UsageError(f"compression method {method!r} takes no --level")
    if level not in levels:
        raise UsageError(
            f"--level {level} is out of range for {method} "
            f"({levels[0]} to {levels[-1]})",
        )


def compression_label(info: ZipInfo) -> str:
    return compressor_names.get(info.compress_type, str(info.compress_type))
