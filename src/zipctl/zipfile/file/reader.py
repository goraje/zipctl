"""Reading the members of a ZipFile."""

from __future__ import annotations

import warnings

from zipctl.compression import Registry
from zipctl.cryptography.aes import AesKeyCache
from zipctl.exceptions import BadZipFile, PasswordRequired
from zipctl.limits import ArchiveLimits
from zipctl.zipfile.ext import ZipExtFile
from zipctl.zipfile.file.encryption import EncryptionSettings, require_bytes
from zipctl.zipfile.file.stream import ArchiveStream
from zipctl.zipfile.file.writer import ArchiveWriter
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.records import read_local_header
from zipctl.zipfile.shared import MASK_ENCRYPTED, user_stacklevel

__all__ = ["ArchiveReader"]


class ArchiveReader:
    """Opens members for reading, decrypting and decompressing them.

    Keeps the WZ-AES keys derived for this archive (:attr:`keys`) so a member
    read twice, or sought backwards in, is not derived again; :meth:`close`
    forgets them.
    """

    def __init__(
        self,
        stream: ArchiveStream,
        writer: ArchiveWriter,
        encryption: EncryptionSettings,
        registry: Registry,
        limits: ArchiveLimits,
        metadata_encoding: str | None,
    ) -> None:
        self.keys: AesKeyCache = AesKeyCache()
        self.limits: ArchiveLimits = limits
        self.metadata_encoding: str | None = metadata_encoding
        self._stream: ArchiveStream = stream
        self._writer: ArchiveWriter = writer
        self._encryption: EncryptionSettings = encryption
        self._registry: Registry = registry

    def open(self, zinfo: ZipInfo, pwd: bytes | None) -> ZipExtFile:
        """Open *zinfo* for reading, positioned at its data.

        *pwd* falls back to the archive's default password.

        Raises:
            ValueError: If the archive is closed or an entry is being written.
            BadZipFile: If the local header is truncated, has a bad signature,
                the filename mismatches the central directory, or entries
                overlap.
            NotImplementedError: If compressed patch data or strong encryption
                are detected.
            PasswordRequired: If the entry is encrypted and no password is
                available.
            BadPassword: If the password does not match the entry.
            TypeError: If *pwd* is not ``bytes``.
        """
        with self._stream.lock:
            self._writer.ensure_idle("read from")
            view = self._stream.share(
                zinfo.header_offset, lambda: self._writer.current is not None
            )
        try:
            read_local_header(view, zinfo, self.metadata_encoding)
            _check_overlap(zinfo, view.tell())
            if zinfo.flag_bits & MASK_ENCRYPTED:
                pwd = pwd or self._encryption.password
                require_bytes("pwd", pwd)
                if not pwd:
                    raise PasswordRequired(
                        f"File {zinfo.orig_filename!r} is encrypted, password "
                        "required for extraction"
                    )
            else:
                pwd = None
            return ZipExtFile(
                view,
                "r",
                zinfo,
                True,
                pwd,
                self._registry,
                self.keys,
                self.limits,
            )
        except BaseException:
            view.close()
            raise

    def close(self) -> None:
        """Forget derived keys."""
        self.keys.clear()


def _check_overlap(zinfo: ZipInfo, data_start: int) -> None:
    """Refuse an entry whose data runs into the next one (a zip bomb trick)."""
    end = zinfo._end_offset  # pyright: ignore[reportPrivateUsage]  # set by the directory reader
    if end is None or data_start + zinfo.compress_size <= end:
        return
    message = f"Overlapped entries: {zinfo.orig_filename!r} (possible zip bomb)"
    if end == zinfo.header_offset:
        warnings.warn(message, stacklevel=user_stacklevel())
    else:
        raise BadZipFile(message)
