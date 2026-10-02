# Public API and failure contracts

## Compatibility scope

The documented root exports in `zipctl.__all__` are the supported import surface.
Compression registry extension interfaces are also supported where documented.
Private attributes, internal filesystem helpers and internal CLI modules are
implementation details. Tests may use them to inject failures; applications
should not depend on them.

The project remains pre-1.0. Record public signature, default, exception and CLI
JSON changes in release notes. Preserve compatible behavior in patch releases;
use a minor release and explicit migration notes for intentional pre-1.0
breaking changes. A future 1.0 release requires explicit acceptance of these
contracts, rather than changing the classifier alone.

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
CRC/authentication as applicable. Closing a partially read member does not
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

## Extraction and publication

Extraction follows archive order. A later explicit directory entry can refer to
a directory created for an earlier child. Rename candidates preserve suffix
chains and are rechecked against extension and custom rules.

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
