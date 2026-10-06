# Public API and failure contracts

## Compatibility scope

The documented root exports in `zipctl.__all__` are the supported import surface.
Compression registry extension interfaces are also supported where documented.
Private attributes, internal filesystem helpers and internal CLI modules are
implementation details. Tests may use them to inject failures; applications
should not depend on them.

Record public signature, default, exception and CLI JSON changes in release
notes. Preserve compatible behavior in patch releases; use a minor release and
explicit migration notes for intentional breaking changes.

## Resource limits and extraction policies

- `ArchiveLimits` is frozen. Each budget accepts a non-negative integer or
  `None`; booleans are rejected. Zstandard windows additionally require a power
  of two from 1 KiB through 2 GiB. Invalid values raise `ValueError`.
- Parser budgets default to the same finite values in the library and the CLI
  (100 000 entries, 64 MiB directory, 32 MiB metadata, 64 MiB LZMA dictionary,
  64 MiB Zstandard window); pass `None` to disable one.
- An archive with more than one end-of-central-directory record that reaches the
  end of the file raises `BadZipFile` ("Ambiguous end of central directory"):
  parsers that choose differently would disagree about its contents.
- `ArchiveResourceLimitError` is separate from `BadZipFile` and from extraction
  policy failures: an otherwise valid archive can exceed the caller's budget.
  It propagates from construction or payload processing and is never converted
  into an advisory policy warning.
- `ExtractPolicy` validates and normalizes direct construction using the same
  field rules as the JSON/mapping loaders. Invalid policy fields raise
  `PolicyConfigError`. Invalid standalone `ExtractPolicyRule` actions raise
  `ValueError`. Normalized collections are immutable.
- Output quotas bound extraction output; they do not impose universal memory or
  CPU limits. Custom compression implementations own their decoder budgets.

## Exceptions

| Exception | Meaning |
| --- | --- |
| `BadZipFile` | Malformed ZIP structures, corrupt payload, failed CRC or authentication |
| `LargeZipFile` | Writing requires ZIP64 while ZIP64 is disabled |
| `PasswordRequired` / `BadPassword` | Missing password or rejected password verifier; both derive from `PasswordError`, a `RuntimeError` |
| `ArchiveResourceLimitError` | A parser or decoder budget was exceeded |
| `PolicyConfigError` | Invalid extraction policy configuration |
| `ExtractionError` | Policy extraction encountered error violations; `.result` contains the structured partial result |
| `ExtractionSecurityError` / `ExtractionMaterializationError` | Direct extraction could not preserve a filesystem invariant or materialize a member |
| `ExtractionQuotaExceeded` | An extraction quota was exceeded; `.code` and `.limit` identify it |
| `NotImplementedError` | Unsupported compression or another explicitly unsupported archive feature |
| `RuntimeError` | A recognized compression method requires an unavailable optional backend |
| `OSError` | Underlying I/O failure where it is not incorporated into a policy extraction result |

These are zipctl exception classes, not aliases of stdlib `zipfile` exceptions.
A password verifier collision may be followed by `BadZipFile` during full
authentication; callers should not interpret verifier acceptance as proof of
integrity. Exception text is diagnostic and not a stable machine-readable API.
Unexpected exceptions from custom callbacks propagate.

## Integrity and lifecycle

Reading a member to EOF validates decompression, declared output size and its
CRC/authentication as applicable. A WinZip AES member's authentication code
follows its data, so bytes read before EOF are not yet authenticated: read to
EOF (or call `verify_integrity()`) before trusting them. `readline()` and line
iteration with no limit buffer up to the member's declared size while looking
for a newline; pass a limit for untrusted members. Closing a partially read member does not
implicitly verify the unread remainder. `verify_integrity()` restarts from the
member's compressed beginning; AES verification authenticates ciphertext, so a
full payload read is still needed to validate decoded size and codec termination.
Successful verification leaves the stream at EOF; a seek can restart it.

One member writer may be active per archive. Completed members can be read
before archive close. Reader registration and archive/writer closure coordinate
within the process; individual member stream positions are not a promise of
safe simultaneous operations from multiple threads. No cross-process lock is
acquired.

Seekable failed member writes can be followed by successful writes and archive
finalization. A failed nonseekable write poisons that archive: further writes
and finalization fail. Finalization errors propagate. Writing/appending directly
to a destination is not a transactional rollback of the entire original file;
use staging and successful atomic publication when that guarantee is needed.

## What WinZip AES authenticates

The WinZip AES HMAC covers a member's ciphertext only. Names, methods, sizes,
timestamps and attributes are not authenticated, so `verify_integrity()` and
`check-password --full` confirm a member's data, not the archive as a whole.

## FIPS

The FIPS deployment test (`tests/deployment/test_fips_provider.py`) runs only
with `ZIPCTL_REQUIRE_FIPS=1` in a FIPS-configured OpenSSL environment.
WinZip AES-128 and AES-192 use 64- and 96-bit PBKDF2 salts. A FIPS provider
requires at least 128 bits and may refuse them; zipctl then raises a
`NotImplementedError` saying so. Use AES-256 (`ZipFileExtra(wz_aes_nbits=256)`) with
FIPS providers. It is a
manual check: CI does not provide such an environment.

## Extraction and publication

Extraction follows archive order.

`extract()`, `extractall()`, `safe_extract()` and `safe_extractall()` all apply
an `ExtractPolicy` (default `ExtractPolicy()`); the `safe_` variants also
return structured results. Extracted files are created with mode `0o666`
masked by the process umask.

- Traversing a symlinked or non-directory parent, leaving the destination, or a
  NUL byte in a symlink target raises `ExtractionSecurityError`.
- Policy extraction does not turn `ValueError` or `RuntimeError` from a member
  into a FAILED result; a missing codec backend propagates like an unsupported
  method.
- Reading a member whose central directory entry shares its local header with
  another entry raises `BadZipFile` (CPython only warns): it is the overlapping
  zip bomb.
- Empty encryption passwords raise `ValueError` for every method.
- Setting `ZipFile.comment` to bytes that embed an end of central directory
  record ending with the comment raises `ValueError` (the archive would be
  ambiguous to read).
- `ZipFile.filelist` is a `tuple` and `ZipFile.NameToInfo` a read-only
  `Mapping` (a `MappingProxyType`); neither copies the directory.
- Local headers carry the entry's own extra fields, as CPython's do.
- A later explicit directory entry can refer to a directory created for an
  earlier child.
- Decompressors: `Registry.get_decompressor(method, flag_bits, limits)` builds
  one for an entry, and a `CompressionEntry.decompressor_factory` takes the same
  flag bits and limits. A codec keeps input it could not process itself and
  reports it through `needs_input` (the reader then calls `decompress(b"")`).
  The codec decides where its stream ends: `decompress` raises `BadZipFile` for
  input after the end, and `finish()`, called once all input is in, raises it
  for a stream that has not ended. Zstandard entries of several frames are read
  completely. A compressor's `flag_bits` go into the entry's headers (the LZMA
  end-marker bit).
- Passwords must be `bytes`.
- `zipctl create` warns when it follows a symbolic link to a file outside the
  directory being added.

`ERROR`, `SKIP` and `RENAME` use no-clobber publication: hard links where
available, otherwise (FAT, exFAT, some network mounts) an exclusive placeholder
that is then replaced, which briefly exposes an empty file. `REPLACE` uses atomic replacement. These guarantees apply per member,
not to an entire extraction batch. Previous successful members can remain after
a later failure; inspect the partial result. Temporary member output is removed
on failure or interruption where the process can still execute cleanup.

The destination is caller-selected and must be trusted. Other processes must
not rearrange it during extraction. Symlink containment is not a guarantee
against future changes to the destination tree. File fsync and atomic visibility
should not be interpreted as a universal power-loss durability guarantee on all
filesystems.

## Strictness compared with `zipfile`

Each of these is described in
`DIFFERENCES.md`.

- Reading refuses duplicate names, data before or after the archive (unless
  `allow_prepended_data=True`), bytes between entries, data descriptors that
  disagree with the central directory, and local/central Unicode path
  mismatches. Backslashes are separators on every platform.
- Writing refuses duplicate names, never changes the caller's `ZipInfo`, aborts
  an entry whose `with` block raises, and refuses an out-of-range
  `compresslevel`. Mode `'a'` refuses a file that is not a valid archive
  instead of appending a new one after it.
- Extraction assesses every member first and writes nothing if any finding is
  an error; `extract()`/`extractall()` use the same policy; `inspect()`
  defaults to `ExtractPolicy()`. Windows device names are written with a `_`
  prefix; FIFOs never take setuid, setgid or sticky bits; rooted or
  drive-relative symlink targets are refused on every platform.
- `ZipFile.copy_member()` returns a `CopiedMember`. `zipctl decrypt --match` and
  `zipctl rewrite` copy members they leave unchanged as stored, without asking
  for their passwords.
- Not available: `filelist`/`NameToInfo` assignment or mutation, `ZipFile.debug`,
  `ZipInfo._compresslevel`.
- CLI: `list --json` reports `"crc32": null` where WZ-AES 2 stores no CRC; a
  decrypted or rewritten copy is never more permissive than its source.
