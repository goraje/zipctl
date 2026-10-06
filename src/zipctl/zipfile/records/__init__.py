"""The record codec: every on-disk ZIP record, read and written in one place.

The local file header and data descriptor of an entry, the central
directory, and the end records.  Everything that knows the archive's byte
layout lives here, so :class:`~zipctl.zipfile.file.ZipFile` and
:class:`~zipctl.zipfile.info.ZipInfo` only deal with typed values.
"""

from zipctl.zipfile.records.central import Directory, looks_like_zip
from zipctl.zipfile.records.end import (
    EndRecord,
    comment_forges_end_record,
    read_end_record,
)
from zipctl.zipfile.records.header import data_descriptor, file_header
from zipctl.zipfile.records.local import (
    DirectoryEntry,
    raise_for_unsupported_flags,
    read_local_header,
)

__all__ = [
    "Directory",
    "DirectoryEntry",
    "EndRecord",
    "comment_forges_end_record",
    "data_descriptor",
    "file_header",
    "looks_like_zip",
    "raise_for_unsupported_flags",
    "read_end_record",
    "read_local_header",
]
