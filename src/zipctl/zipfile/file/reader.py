"""Reading the members of a ZipFile."""

from __future__ import annotations

from collections.abc import Generator

from zipctl.compression import Registry
from zipctl.cryptography.aes import AesKeyCache
from zipctl.exceptions import BadZipFile, PasswordRequired
from zipctl.format import read_exactly
from zipctl.limits import ArchiveLimits
from zipctl.zipfile.encryption import EncryptionSettings, require_bytes
from zipctl.zipfile.file.ext import ZipExtFile
from zipctl.zipfile.file.stream import ArchiveStream
from zipctl.zipfile.info import ZipInfo
from zipctl.zipfile.records import Directory, read_local_header
from zipctl.zipfile.shared import CHUNK

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
        directory: Directory,
        encryption: EncryptionSettings,
        registry: Registry,
        limits: ArchiveLimits,
        metadata_encoding: str | None,
    ) -> None:
        self.keys: AesKeyCache = AesKeyCache()
        self.limits: ArchiveLimits = limits
        self.metadata_encoding: str | None = metadata_encoding
        self._stream: ArchiveStream = stream
        self._directory: Directory = directory
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
            self._stream.ensure_not_writing("read from")
            view = self._stream.share(zinfo.header_offset, lambda: self._stream.writing)
        try:
            entry = self._directory.entry(zinfo)
            read_local_header(view, entry, self.metadata_encoding)
            if zinfo.is_encrypted:
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
                zinfo,
                pwd,
                self._registry,
                self.keys,
                self.limits,
                entry.dos_time,
            )
        except BaseException:
            view.close()
            raise

    def stored_chunks(self, zinfo: ZipInfo) -> Generator[bytes, None, None]:
        """Yield *zinfo*'s data exactly as stored: still encrypted and compressed.

        The local header is validated first, as for :meth:`open`.  Nothing is
        decrypted, so nothing is checked beyond the archive's structure.

        Raises:
            ValueError: If the archive is closed or an entry is being written.
            BadZipFile: If the header is invalid or the data is truncated.
        """
        with self._stream.lock:
            self._stream.ensure_not_writing("read from")
            view = self._stream.share(zinfo.header_offset, lambda: self._stream.writing)
        try:
            read_local_header(
                view, self._directory.entry(zinfo), self.metadata_encoding
            )
            left = zinfo.compress_size
            while left > 0:
                try:
                    chunk = read_exactly(view, min(left, CHUNK))
                except EOFError:
                    raise BadZipFile(
                        f"Truncated data for {zinfo.orig_filename!r}"
                    ) from None
                left -= len(chunk)
                yield chunk
        finally:
            view.close()

    def close(self) -> None:
        """Forget derived keys."""
        self.keys.clear()
