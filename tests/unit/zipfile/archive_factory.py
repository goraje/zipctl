"""Small archive fixture shared by malformed-input and lifecycle regressions."""

import io

from zipctl import ZipFile


def archive_bytes(method: int = 0, encryption: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with ZipFile(buffer, "w", compression=method, encryption=encryption) as archive:
        archive.setpassword(b"password")
        archive.writestr("file.txt", b"payload")
    return buffer.getvalue()
