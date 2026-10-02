<p align="center">
	<img src="https://raw.githubusercontent.com/goraje/zipctl/main/assets/zipctl-logo.svg" alt="zipctl logo" width="380">
</p>

<p align="center">
	<img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-245bcf?style=flat-square&logo=python&logoColor=white" alt="Supported Python versions: 3.10, 3.11, 3.12, 3.13, 3.14">
	<img src="https://img.shields.io/badge/license-MIT-245bcf?style=flat-square" alt="License: MIT">
</p>

`zipctl` is a standalone ZIP library derived from CPython's `zipfile`
module, extended with WinZip AES support adapted from pyzipper.

The project aims to provide a `zipfile`-style API for applications that need
to read and write standard ZIP archives, WinZip AES-encrypted archives and
traditional ZipCrypto archives.

## Why this project exists

`zipctl` started as a split-off from pyzipper for deployments that need to
use the `cryptography` package with a FIPS-configured OpenSSL provider.
Pyzipper uses PyCryptodomeX for its cryptographic primitives, which is outside
the FIPS-validated cryptographic boundary used by those deployments.

This project is not itself FIPS-validated and using `cryptography` does not
make an application FIPS-compliant. A deployment must use a FIPS-validated
cryptographic module and a FIPS-configured Python/OpenSSL environment, and
must follow the applicable operational controls. For a FIPS-constrained
deployment, use WinZip AES only after confirming that the selected provider
permits the algorithms and modes required by the WinZip AES format. Do not use
the legacy ZipCrypto option for FIPS-constrained data; it is a compatibility
feature and is not a FIPS-approved encryption algorithm.

WinZip AES output uses AES version 2 by default. Version 2 omits the plaintext
CRC-32 from ZIP metadata, reducing offline candidate-guessing disclosure.
Select `ZipFileExtra(force_wz_aes_version=1)` only when compatibility with a
consumer that requires AES version 1 is more important than that metadata
protection; version 1 stores the plaintext CRC-32 in both ZIP headers.

## What it provides?

- a familiar `ZipFile` API.
- read and write support for plain ZIP archives
- write support for WinZip AES and ZipCrypto encryption
- read support that auto-detects AES vs. ZipCrypto for encrypted members
- support for `ZIP_STORED`, `ZIP_DEFLATED`, `ZIP_BZIP2`, `ZIP_LZMA` and
  `ZIP_ZSTANDARD` compression

ZIP LZMA archives declare their dictionary size in the member stream. zipctl
rejects dictionaries larger than the configured budget (64 MiB by default) before
constructing a decompressor.
This bounds attacker-controlled allocation while retaining compatibility with
normal ZIP LZMA archives; applications handling untrusted archives should also
apply extraction size and compression-ratio limits.

## Installation

```bash
pip install zipctl
```

## Intended usage

The intended usage is the same as `zipfile`'s: use `zipctl.ZipFile` to create your archive, optionally choose a compression and/or encryption methods and
set a password for encrypted archives if applicable.

### Creating a plain ZIP archive

```python
from zipctl import ZipFile, ZIP_DEFLATED

with ZipFile("example.zip", "w", compression=ZIP_DEFLATED) as zf:
    zf.writestr("hello.txt", "hello world")
```

### Reading a plain ZIP archive

```python
from zipctl import ZipFile

with ZipFile("example.zip", "r") as zf:
    data = zf.read("hello.txt")
```

### Writing an AES-encrypted archive

```python
from zipctl import ZipFile, WZ_AES, ZIP_DEFLATED

password = b"correct horse battery staple"

with ZipFile(
    "secret-aes.zip",
    "w",
    compression=ZIP_DEFLATED,
    encryption=WZ_AES,
) as zf:
    zf.setpassword(password)
    zf.writestr("secret.txt", b"sensitive payload")
```

### Reading an encrypted ZIP archive

```python
from zipctl import ZipFile

password = b"correct horse battery staple"

with ZipFile("secret-aes.zip", "r") as zf:
    zf.setpassword(password)
    data = zf.read("secret.txt")
```

> **NOTE**:
When reading, encryption is normally detected automatically from the archive
metadata, so you typically do not need to specify an encryption mode.

### Customizing AES settings with `ZipFileExtra`

`ZipFileExtra` is the write-time configuration object for AES-specific ZIP
output. It lets you override the WinZip AES version written into the extra
field and choose the AES key size.

```python
from zipctl import ZipFile, ZipFileExtra, WZ_AES, ZIP_DEFLATED

password = b"correct horse battery staple"
extra = ZipFileExtra(force_wz_aes_version=1, wz_aes_nbits=256)

with ZipFile(
    "secret-aes-v1.zip",
    "w",
    compression=ZIP_DEFLATED,
    encryption=WZ_AES,
    extra=extra,
) as zf:
    zf.setpassword(password)
    zf.writestr("secret.txt", b"payload")
```

### Writing AES-encrypted archive with a different key size

```python
from zipctl import ZipFile, ZipFileExtra, WZ_AES

password = b"correct horse battery staple"
extra = ZipFileExtra(wz_aes_nbits=128)

with ZipFile("secret-aes-128.zip", "w", encryption=WZ_AES, extra=extra) as zf:
    zf.setpassword(password)
    zf.writestr("secret.txt", b"payload")
```

### Writing a ZipCrypto-encrypted archive

```python
from zipctl import ZipFile, ZIP_CRYPTO, ZIP_DEFLATED

password = b"correct horse battery staple"

with ZipFile(
    "secret-zipcrypto.zip",
    "w",
    compression=ZIP_DEFLATED,
    encryption=ZIP_CRYPTO,
) as zf:
    zf.setpassword(password)
    zf.writestr("secret.txt", b"legacy compatible payload")
```

ZipCrypto is retained for legacy interoperability only. It is not a modern
confidentiality mechanism and is unsuitable for FIPS-constrained or otherwise
security-sensitive new archives; use WinZip AES instead.

### Using in-memory buffers

```python
import io

from zipctl import ZipFile, WZ_AES

password = b"correct horse battery staple"
buffer = io.BytesIO()

with ZipFile(buffer, "w", encryption=WZ_AES) as zf:
    zf.setpassword(password)
    zf.writestr("data.txt", b"payload")

buffer.seek(0)

with ZipFile(buffer, "r") as zf:
    zf.setpassword(password)
    data = zf.read("data.txt")
```

### Per-entry encryption

Archive-level encryption remains the default for newly written members, but
individual entries can override it. Use `INHERIT_ENCRYPTION` to make
inheritance explicit, `None` for a plaintext member, or an encryption method
for a protected member.

```python
from zipctl import INHERIT_ENCRYPTION, ZIP_CRYPTO, WZ_AES

with ZipFile("mixed.zip", "w", encryption=WZ_AES) as zf:
    zf.setpassword(b"default-password")
    zf.writestr("secret.txt", b"secret")
    zf.writestr("public.txt", b"public", encryption=None)
    zf.writestr(
        "legacy.txt",
        b"legacy",
        encryption=ZIP_CRYPTO,
        password=b"legacy-password",
    )
    zf.writestr("inherited.txt", b"inherited", encryption=INHERIT_ENCRYPTION)
```

An entry-level password overrides the archive default password. Per-entry
encryption is part of the ZIP format, but consumers vary in their support for
mixed algorithms or multiple passwords in one archive.

### Safe extraction with a policy

`extract()` and `extractall()` behave like the standard library's: no limits
apply, and symlink and special-file members (FIFOs, devices) are written as
regular files holding their payload. Path traversal is still neutralised.

For untrusted archives use `safe_extract()` / `safe_extractall()`. They check
every member against an `ExtractPolicy` (by default `ExtractPolicy()`: no
traversal, symlinks, special files or overwrites, finite size, count and ratio
limits) and return structured results describing every member.

```python
from zipctl import ExtractPolicy, ViolationAction

with ZipFile("input.zip") as zf:
    result = zf.safe_extractall(
        "out",
        policy=ExtractPolicy(
            on_violation=ViolationAction.SKIP,
            max_compression_ratio=100.0,
        ),
    )

for member in result.members:
    print(member.member, member.status, member.violations)
```

`ExtractPolicy` can enforce path, overwrite, file-size, archive-size,
entry-count, compression-ratio, extension, duplicate-target, and file-type
limits. Set `preview_only=True` for a dry run. Policy violations configured as
errors raise `ExtractionError`, whose `result` attribute contains the partial
structured result. Size limits are enforced both from archive metadata before
extraction and against actual bytes written during extraction; an actual-size
quota breach aborts that member and removes its partial output.
`WARN` size rules are advisory during both assessment and extraction; `ERROR`
and `SKIP` rules enforce runtime quotas with their respective actions.

### Progress reporting

All four extraction methods accept `progress=`, a callable that receives a
frozen `ProgressEvent` as each member starts, roughly every MiB while its data
is written, and when it finishes:

```python
def show(event: ProgressEvent) -> None:
    if event.phase is ProgressPhase.FINISH:
        print(f"{event.member}: {event.status.value} "
              f"({event.total_bytes_done}/{event.total_bytes} bytes)")

with ZipFile("input.zip") as zf:
    zf.safe_extractall("out", progress=show)
```

Sizes come from the archive's declared metadata, so treat them as hints. The
callback runs in the extracting thread and must not write to the same
`ZipFile`. To cancel, raise from the callback: members already extracted stay
on disk, the member in flight leaves no partial file, and your exception
propagates unchanged (it is not turned into a per-member failure). With a
callback, `members` is resolved up front, so an unknown name raises `KeyError`
before anything is written.

### Per-member passwords on extraction

`pwd=` of every extraction method may also be a callable taking a
`ZipInfo` and returning that member's password (or `None`). It is asked only
for encrypted members, which suits archives protected per entry:

```python
passwords = {"a.txt": b"one", "b.txt": b"two"}

with ZipFile("per-entry.zip") as zf:
    zf.extractall("out", pwd=lambda info: passwords.get(info.filename))
```

### Policy files (JSON)

An `ExtractPolicy` can be loaded from, and written to, plain JSON, so rulesets
live in a file instead of code. The field names are exactly the policy's field
names; `policy_to_json(ExtractPolicy())` prints a complete starting document.

```python
policy = zipctl.policy_from_json(Path("rules.json").read_text())
with ZipFile("input.zip") as zf:
    zf.safe_extractall("out", policy=policy)
```

```json
{
  "version": 1,
  "on_violation": "skip",
  "max_entries": 500,
  "max_member_size": {"value": 52428800, "on_violation": "error"},
  "max_compression_ratio": null,
  "blocked_extensions": [".exe", ".dll"],
  "overwrite_policy": "rename"
}
```

- Every field is optional; missing ones keep their default. Pass `base=` to
  layer documents, so a later document overrides only what it mentions.
- Limits are non-negative integers (`max_compression_ratio` is a positive
  number); `null` disables one. Booleans must be real JSON booleans.
- A field that accepts a per-rule action may be a bare value or
  `{"value": ..., "on_violation": "error|warn|skip"}`. A rule around `null` collapses
  to plain `null`, since there is no limit to act on.
- Extensions look like `".txt"` or `".tar.gz"` (or `""` for files without one)
  and are lower-cased. An entry matches any trailing chain of a name's
  suffixes: `".gz"` matches `x.tar.gz` and `x.gz`, while `".tar.gz"` matches
  only names ending in `.tar.gz`.
- Loading is strict. Unknown fields (with a "did you mean" hint), wrong types,
  duplicate keys and `NaN`/`Infinity` are errors, and a `PolicyConfigError`
  lists every problem at once (`error.issues` holds `(path, message)` pairs).
- `custom_validator` is Python code and cannot be expressed in JSON.

### Checking a password

`ZipFile.check_password()` tells you whether a password matches the encrypted
members without extracting anything:

```python
with ZipFile("secret.zip") as zf:
    result = zf.check_password(b"hunter2")
    if not result.ok:
        print("rejected:", result.rejected)
```

By default it only checks each member's password verifier, so no data is read.
A rejection is definitive, but an acceptance only means the password is
probably right: a wrong password still passes about 1 time in 256 for ZipCrypto
and 1 in 65,536 for WinZip AES. Pass `full=True` for a definitive answer: it
authenticates each member (the AES HMAC, or the CRC-32 for ZipCrypto), which
reads the member. A member whose data fails that check is reported as
`corrupt` rather than `rejected`. Unencrypted members are reported as
`unencrypted` and never cause a failure. Opening an encrypted member without a
password raises `PasswordRequired`, and a wrong one raises `BadPassword`; both
are `RuntimeError` subclasses.

### Metadata-only inspection

Use `ZipFile.inspect()` to produce a structured report before extraction.
Inspection reads the central directory and member metadata only: it never
opens, decompresses, decrypts, or writes a payload, and policy findings never
raise `ExtractionError`.

```python
from zipctl import ExtractPolicy, ZipFile

with ZipFile("input.zip") as zf:
    report = zf.inspect(policy=ExtractPolicy(max_compression_ratio=100.0))

print(report.total_entries, report.total_uncompressed_size)
print(report.suspicious_paths, report.encrypted_members)
print(report.duplicate_member_names, report.duplicate_targets)
for member in report.members:
    print(member.member, member.violations)
```

The report separately identifies duplicate member names and duplicate
filesystem targets, suspicious paths, encrypted members, symlinks and special
files, large members, compression-ratio outliers, and entry/size policy
findings. `path=` controls the destination used for non-mutating target
resolution; it does not create or modify that path.

## Command line

`zipctl` (or `python -m zipctl`) inspects and verifies archives without writing
any code. It needs nothing beyond zipctl itself.

```
zipctl list     ARCHIVE [MEMBER ...] [-l] [--json]      # names, or a table with -l
zipctl test     ARCHIVE [MEMBER ...] [-v|-q] [--progress] [--json]  # check integrity
zipctl inspect  ARCHIVE [-d DIR] [-q] [--json]          # what extraction would flag
zipctl create   ARCHIVE PATH ... [-C DIR] [--exclude GLOB] [-n]  # build an archive
zipctl extract  ARCHIVE [MEMBER ...] [--match GLOB] [-d DIR]  # policy-guarded extraction
zipctl check-password ARCHIVE [MEMBER ...] [--full] [-v] [--json]
zipctl encrypt  IN OUT [--encryption METHOD] [--match GLOB ...]   # protect a plain archive
zipctl decrypt  IN OUT [--match GLOB ...]                     # remove the protection
zipctl rewrite  IN OUT [--compression METHOD] [--encryption ...]  # change method, password, compression
zipctl policy show     [--policy FILE] [--policy-json TEXT]
zipctl policy validate FILE [FILE ...] [--json]
```

- Shell completion is optional: `pip install "zipctl[completion]"`, then
  `zipctl --print-completions fish > ~/.config/fish/completions/zipctl.fish`
  (`bash`, `zsh` and `tcsh` work too; each shell's own documentation says where
  its completion scripts go).
- `list` prints member names; `-l` adds a table with the mode, sizes, compression
  ratio, date, method, protection and CRC of each member, a total line, and the
  archive comment. `MEMBER` may be an exact name or a pattern (`*` and `?` stay
  inside one directory, `**` crosses directories, `[abc]` is a character class; a
  name containing those characters also matches literally, and a pattern that
  matches nothing is an error). `test` and `check-password` take the same
  patterns.
- `test` reads every member (or the `MEMBER`s you name) and reports each bad one
  (not just the first). It exits `1` if any member fails. Encrypted members need a
  password (below). `-q` prints nothing unless a member fails, and `--progress`
  reports each member on standard error.
- `inspect` reads only metadata, so it works on damaged or encrypted archives
  without a password. It applies the same default policy as extraction (or the
  one you give with `--policy` / `--policy-json`, see "Policy files (JSON)") and
  exits `1` if any violation would make extraction fail; `skip`- and `warn`-level
  findings are listed but do not fail the run. `-q` prints nothing for a clean
  archive and only the violations and the verdict otherwise.
- `create` adds files and directories recursively (`.` adds the contents of the
  current directory; `-C DIR` takes paths relative to `DIR` and stores them
  without it). Names are stored as given, minus any leading `/`; a path that
  climbs out of the current directory (`../x`) is refused unless you choose the
  base with `-C`. By default symbolic links to files are stored as their
  content, and links to directories, broken links and special files (pipes,
  devices) are skipped with a warning; `--symlinks store` keeps every link
  (also directory and broken ones) as a link entry instead, and `--symlinks skip`
   leaves them all out. Links are never followed into directories during recursive
   discovery. Stored link targets are encrypted according to the same protection
   rules as files. Extraction refuses stored links unless the policy allows
  them (`"allow_symlinks": true`), and even then one that points out of the
  destination. `--exclude GLOB` (repeatable) leaves out what matches: a pattern
  without a `/` matches the last name at any depth (`'*.pyc'`, `.git`), one with
  a `/` matches the whole archive name (`'build/**'`), and a matching directory
  is skipped with everything in it; an exclude that matches nothing is reported
  as a warning. `-n/--dry-run` runs every check, lists what would be added (with
  the protection each file would get) and writes nothing; it does not ask for
  typed passwords. `--progress` reports each entry on standard error. Compression is `-m store|deflate|bzip2|lzma|zstd` (default
  `deflate`) with `-L LEVEL`. The archive is written to a scratch file beside it
  and moved into place only when everything succeeded, so a failed or
  interrupted run leaves nothing behind. An existing archive is refused unless
  you pass `--force` (replace) or `--append` (add members, keeping the rest; it
  is rewritten through a copy, and names already in it are an error).
  - `--encryption aes256|aes192|aes128|zipcrypto|none` protects every file with one
    password (from `--password-file`, `--password-stdin`, `ZIPCTL_PASSWORD`, or
    typed twice at a terminal). `--wz-aes-version 1` writes the older AES format
    for tools that need it; ZipCrypto is weak and prints a warning.
  - `--protect 'GLOB[=METHOD]'` (repeatable) protects the members matching `GLOB`
    with a password of their own, asked for at a terminal. The first matching
    rule wins, members no rule matches follow `--encryption` (or stay plain), and
    `GLOB=none` carves out plain members. A rule that decides no member is an
    error, so a typo cannot leave files unprotected.
  - `--encryption-spec FILE` (`-` is standard input) is the scriptable form: a
    JSON file of the same rules whose passwords are references, never values:

    ```json
    {
      "version": 1,
      "default": {"method": "aes256", "password": {"env": "ZIPCTL_PASSWORD"}},
      "rules": [
        {"match": "secrets/**", "method": "aes256", "password": {"file": "/run/secrets/vault"}},
        {"match": "*.key", "method": "aes128", "password": {"prompt": "Password for keys"}},
        {"match": "public/**", "method": "none"}
      ]
    }
    ```

    A password is exactly one of `{"env": NAME}`, `{"file": PATH}`,
    `{"prompt": LABEL}` or `{"stdin": true}` (at most once). Unknown keys,
    inline passwords, duplicate patterns and unusable references are reported
    together and exit `2`. It cannot be combined with `--encryption`, `--protect`
    or the password options.
- `extract` applies the default extraction policy unless told otherwise, so
  traversal, absolute paths, symlinks, special files and compression bombs are
  refused per member (each is listed as `FAILED`/`SKIPPED` with the reason; the
   rest is still extracted, and the exit code is `1`). It takes `MEMBER` names
   or patterns (an unmatched selection fails before anything is written),
  `--match GLOB` (repeatable) to add members by pattern (a pattern that matches
  nothing is an error),
  `-d DIR` (default: the current directory), the `--policy` / `--policy-json`
  options, `--overwrite {error,skip,replace,rename}` (default `error`: existing
  files are never touched), `--dry-run` (report what would happen, write
  nothing, do not create `DIR`), `--no-fsync`, `--progress`, and `-q` / `-v`.
  `--no-policy` uses plain extraction like the standard library's (path
  traversal is still neutralised, but no limits apply and symlinks and special
  files are written as regular files) and cannot be combined with the options
  that configure the policy.
- `check-password` answers "is this the password?" without extracting. It
  takes one password (from a file, standard input, `ZIPCTL_PASSWORD` or a single
  prompt, never as an argument) and tests it against every encrypted member, or
  against the `MEMBER` names / patterns you give (`*` and `?` stay inside one
  directory, `**` crosses directories, `[abc]` is a character class; a name
  containing those characters also matches literally, and a pattern that matches
  nothing is an error). It exits `0` when no member rejects the password and `1`
  otherwise, listing each `REJECTED` or `CORRUPT` member. By default only the
  password verifier is checked, so a wrong password can still pass (about 1 in
  256 for ZipCrypto, 1 in 65,536 for AES); `--full` also authenticates each
  member's data, which is definitive but reads them. An archive with no
  encrypted members has nothing to reject and exits `0`.
- `encrypt`, `decrypt` and `rewrite` copy `IN` into a **new** archive `OUT`; they
  never work in place (`OUT` may not be `IN`, even with `--force`, or a link to
  it), and an existing `OUT` is refused unless you pass `--force`. Members are
  streamed one at a time, so size is no problem. Each keeps its name, date,
   mode, comment and compression method, and so does the archive comment.
   Extra fields such as timestamps and ownership are preserved; ZIP64, AES and
   Unicode-path fields are rebuilt or omitted as appropriate. When compression
   is unchanged, compressed bytes can be copied directly, with decryption and
   re-encryption as needed. Changing compression decompresses and recompresses
   the payload. `OUT` is written beside its final name, **read back and compared**
   with what was copied (names, dates, modes, comments, protection, and each
   member's size and CRC-32) and only then moved into place, so a failed check, a wrong
  password, a full disk or Ctrl-C leaves `OUT` untouched and no scratch file
  behind. `--no-verify` skips the read-back. Output is `-q`/`-v`/`--json` like
  `create`.
  - `encrypt IN OUT` gives every file `--encryption aes256|aes192|aes128|zipcrypto`
    (default `aes256`; `--wz-aes-version 1` for old tools) with one password: from
    `--password-file`, `--password-stdin`, `ZIPCTL_PASSWORD`, or typed twice at a
    terminal. `--match GLOB` (repeatable) protects only the matching files. A
    pattern that matches nothing is an error, and so is an input that already
    has encrypted members (use `rewrite` for those).
  - `decrypt IN OUT` needs the passwords of the encrypted members, read like
    `test` does (sources first, then a prompt per distinct password).
    `--match GLOB` decrypts only those members; the others stay encrypted with
    their own scheme and password, so all passwords are still needed. An input
    with nothing encrypted is an error.
  - `rewrite IN OUT` changes what you ask for and keeps the rest. Members are
    unlocked with `--old-password-file`, `--old-password-stdin`,
    `ZIPCTL_OLD_PASSWORD`, or a prompt, and protected again by the same options
    as `create` (`--encryption`, `--protect`, `--encryption-spec`,
    `--wz-aes-version`, whose passwords come from the ordinary password
    options); a member that no rule covers keeps its current scheme and password.
    So `--encryption aes256` changes everything to one new password, `--encryption
    none` decrypts, `--protect 'secrets/**'` re-protects just those, and no
    encryption option at all only recompresses. `--compression
    store|deflate|bzip2|lzma|zstd` (with `-L LEVEL`) sets the compression of
    every member.
- Member names come from the archive and can contain terminal escape sequences,
  so human-readable output escapes anything unprintable (`\x1b`, `\u202e`).
  `--json` output is plain ASCII and keeps names exactly.
- `--json` prints one JSON document on standard output; problems go to standard
  error as `zipctl: error: ...`, and are also written to standard output as
  `{"ok": false, "error": ..., "code": N, "details": [...]}` so a script can read
  one stream. (A command line argparse rejects, exit `2`, is reported as plain
  text only.)
- `ZIPCTL_POLICY` names a policy file that `extract`, `inspect` and `policy show`
  start from, under `--policy` and `--policy-json`; `extract --no-policy` ignores
  it. It is a default for convenience, not a control: anyone can override it with
  `--policy`. `ZIPCTL_DEBUG=1` prints the traceback of an error, and an error the
  CLI did not expect is otherwise reported as `zipctl: error: unexpected ...`.

Exit codes: `0` success, `1` the operation ran and failed (a bad member, policy
violations, an unreadable archive), `2` a bad command line or configuration
file, `130` interrupted (Ctrl-C), `141` the reader of the output went away.

Passwords are never accepted as arguments, since they would show up in process
listings and shell history. They come from, in this order: `--password-file
FILE` and/or `--password-stdin` (the first line), else the `ZIPCTL_PASSWORD`
environment variable (`--password-prompt` skips the variable and asks at the
terminal instead). When a terminal is attached and no source has the right
password, you are asked for the password of each encrypted member that needs
one; every accepted password is remembered, so an archive whose members share a
password asks once, and one with several passwords asks once per password. Three
wrong tries fail that member; an empty answer (or Ctrl-D) stops asking. Typed
passwords are masked with `*` on Python 3.14+; older Pythons prompt silently.
Password selection for reading commands verifies candidate passwords against
the member's integrity data before remembering them. A lightweight verifier
collision therefore does not prevent trying the remaining passwords. This
adds an integrity pass for encrypted members; `check-password` retains its
explicit lightweight/default and `--full` modes.

## Public API

The package exports these primary entry points:

- `ZipFile`
- `ZipInfo`, `BadZipFile`, `LargeZipFile`
- `ArchiveLimits`, `ArchiveResourceLimitError`
- `is_zipfile`
- `INHERIT_ENCRYPTION`
- `ExtractPolicy`, `ExtractResult`, `ExtractMemberResult`, `ExtractionError`
- `InspectionMember`, `InspectionResult`
- `ZipFileExtra`
- `WZ_AES`, `WZ_AES_V1`, `WZ_AES_V2`
- `ZIP_CRYPTO`
- `ZIP_STORED`, `ZIP_DEFLATED`, `ZIP_BZIP2`, `ZIP_LZMA`, `ZIP_ZSTANDARD`
- `WzAesExtra`

### Assessment And Extraction

Policy-enabled extraction is a two-stage operation. Metadata is assessed first;
only members whose effective policy action permits it are materialized. The
assessment stage does not open, decrypt, decompress, or write member payloads.
`ZipFile.inspect()` exposes this metadata-only behavior through an
`InspectionResult`. `MemberAssessment` describes the normalized target, entry
type, and violations for one member; `ArchiveAssessment` is available for
applications that need to build security tooling around the shared assessment
model.

For callers that need the shared lower-level model directly, use
`ZipFile.assess()`:

```python
with ZipFile("input.zip") as zf:
    assessment = zf.assess(
        "out",
        ExtractPolicy(max_compression_ratio=100.0),
    )

for member in assessment.members:
    print(member.info.filename, member.target, member.violations)
```

`ViolationAction.ERROR`, `WARN`, and `SKIP` control ordinary policy findings.
`ExtractPolicy.custom_validator` takes a callable `(ZipInfo, Path) -> None` or a
sequence of them. Each validator runs for every member; one that raises
`ValueError`, `OSError`, `RuntimeError` or `BadZipFile` adds a
`custom_validator` violation carrying the exception message, and the remaining
validators still run.
`max_entries` applies to the archive as a whole and is reported once: `ERROR`
extracts nothing, `SKIP` extracts only the first `max_entries` members, and
`WARN` warns and extracts everything.
Security-critical path and file-type findings remain errors when `WARN` is
selected. `preview_only=True` performs assessment and returns member results
without creating or modifying the destination; `previewed_count` counts the
members it would extract (they are not in `skipped_count`). An `ExtractionError` contains
the partial `ExtractResult` in its `result` attribute.

Regular files are written to a temporary file in the destination directory and
atomically committed only after the member has been fully read and quota checks
have succeeded. Existing files are therefore preserved when a member fails.
Each file is fsynced before it is moved into place; pass
`ExtractPolicy(fsync_files=False)` to skip that when extraction throughput matters
more than durability across power loss.
Symlinks and special files are rejected by default. Allowed symlinks are
checked for indirect escapes through existing symlinks as well as absolute
and parent-traversal targets. Their target text is limited to 64 KiB. They are
materialized without following their targets, and supported FIFOs can be
materialized on platforms that provide `os.mkfifo`. Descriptor-backed
no-follow checks are used where the platform exposes the required APIs; other
platforms use the strongest path-based checks available.
The destination must not be concurrently rearranged by an untrusted process:
symlink targets can change after validation, and path-based platforms cannot
provide descriptor-relative containment. No-overwrite commits use exclusive
hard links and fail rather than silently replacing a concurrent file. A
filesystem without hard-link support (FAT, exFAT, some network mounts) falls
back to an exclusive placeholder that is then replaced: existing files are still
never overwritten, but an empty placeholder is briefly visible. Replacement
uses atomic rename. The same no-clobber rule applies to CLI archive creation.

Unicode Path metadata determines the effective extraction name; policy checks
and materialization use that same name. Original ZIP names remain available
for local-header validation and are preserved when appending to an archive.

Extraction preserves archive order. Parents created during the current extraction
are accepted when their explicit directory entry appears later; pre-existing
targets remain subject to the overwrite policy. Rename mode inserts a counter
before the suffix chain (`file.1.tar.gz`) and checks the candidate against extension
and custom validation rules. Explicit CLI `--overwrite` overrides a loaded
`overwrite_policy`. The older `allow_overwrite: true` is still accepted, with a
`DeprecationWarning`, and means `overwrite_policy: "replace"`.

Direct `ExtractPolicy(...)` construction validates limits, actions and extensions
just like JSON loading. Extension rules are normalized to lowercase.

### Public API contracts

See [Public API contracts](docs/public-api.md) for compatibility, exceptions,
integrity verification and lifecycle guarantees.

### Archive resource budgets

`ExtractPolicy` limits output. `ArchiveLimits` additionally limits work performed
while opening an archive and initializing built-in decoders:

```python
from zipctl import ArchiveLimits, ZipFile

limits = ArchiveLimits(
    max_entries=100_000,
    max_directory_bytes=64 << 20,
    max_metadata_bytes=32 << 20,
    max_lzma_dictionary_bytes=64 << 20,
    max_zstd_window_bytes=64 << 20,
)
with ZipFile("input.zip", limits=limits) as archive:
    print(archive.namelist())
```

Counts and directory sizes are checked before record parsing; actual member count
and cumulative encoded names, extra fields and comments are checked incrementally
before reading variable-length fields. Metadata includes the archive comment.
LZMA dictionaries and Zstandard windows are bounded separately. Zstandard window
budgets must be powers of two between 1 KiB and 2 GiB.

Exceeding a budget raises `ArchiveResourceLimitError`. Parser budgets abort opening;
decoder budgets abort payload processing. These errors are not downgraded by
extraction policy actions. CLI `test` records a decoder failure for the member and
continues testing the remaining members.

`ArchiveLimits()` defaults to the finite values shown above in the library and
in the CLI alike; pass `None` for a budget to disable it. Override them on the
command line with
`--archive-max-entries`, `--archive-max-directory-bytes`,
`--archive-max-metadata-bytes`, `--archive-max-lzma-dictionary-bytes`, or
`--archive-max-zstd-window-bytes`. Values are counts or bytes (`64MiB`, `512K` and so on); `none` disables a budget.
`--max-ratio N|none` overrides the policy's compression-ratio limit (default 100).
These bound specific resources, not total process memory or CPU time. Custom
compression-registry implementations must enforce their own decoder budgets.

### Lifecycle and coordination

Completed members can be read before closing a writable archive. Shared archive
stream access, reader registration and close are coordinated within a process;
only one member writer may be active. This is not cross-process file locking.
Use external coordination when multiple processes modify the same archive.

Failed writes on seekable output can be followed by successful writes; finalization
truncates abandoned trailing bytes. Non-seekable output cannot roll back a partial
write: subsequent writes and archive finalization raise, and the caller must discard
that output. Archive-level finalization errors are propagated.

`ZipExtFile.verify_integrity()` restarts verification from the beginning, even after
a read or seek, and consumes the member. AES checks authenticate the ciphertext;
reading the decompressed payload is still required to validate its codec and size.
Repeated verification is supported. Merely closing a partially read member does
not verify its integrity.

### Compression Registries

Each `ZipFile` receives an archive-local snapshot of the compression registry.
Applications can provide a custom `Registry` with the `compression_registry=`
constructor option. Registering or replacing a method in one archive does not
change other archives or the module-level default registry. Stored entries use
the same no-op compressor/decompressor strategy as other compression methods.
The snapshot is taken when the archive is constructed, so later changes to the
module-level registry do not affect an existing `ZipFile`.

### ZipInfo Compatibility Names

ZIP header serialization is side-effect-free: calling `ZipInfo.FileHeader()` or
`ZipInfo.central_directory()` calculates effective ZIP versions without
rewriting the `ZipInfo` object's `create_version` or `extract_version` fields.
Prefer these correctly spelled data-descriptor APIs:

- `use_data_descriptor`
- `encode_data_descriptor()`
- `data_descriptor()`

The historical CPython-derived spellings remain supported as compatibility
aliases: `use_datadescripter`, `encode_datadescripter()`, and
`datadescripter()`. The `_compresslevel` alias likewise remains available for
compatibility with code using the CPython-style metadata attribute.

## Notes

- `ZIP_ZSTANDARD` compression uses stdlib `compression.zstd` (Python 3.14+); on
  Python 3.10-3.13 install the optional extra (`pip install "zipctl[zstd]"`,
  which pulls in `backports.zstd`), otherwise using it raises `RuntimeError`
- ZIP archives that span multiple disks are not supported (same as the standard
  library) and are rejected with `BadZipFile`
- only one write handle may be open per archive at a time; opening a second
  one, or reading while a writer is active, raises `ValueError`
- use WinZip AES for modern encrypted ZIP workflows (ZipCrypto is mainly for compatibility with older tools)
- passwords must be byte strings
- decompression is streamed and bounded per read, but callers should still
  enforce application-level limits on total extracted bytes and archive member
  counts when processing untrusted archives
- central-directory records are read and written incrementally; the archive
  still retains one `ZipInfo` per entry in memory, before extraction policies
  are assessed

## Interoperability

The project is intended to interoperate with common ZIP tooling while exposing
an API that feels like the standard library.

- the functional test suite includes 7-Zip interoperability checks in both
	directions: archives written by `zipctl` are validated by 7-Zip, and
	AES- and ZipCrypto-encrypted archives written by 7-Zip are read by
	`zipctl`
- the same holds for the command line: 7-Zip reads what `create`, `encrypt`,
	`decrypt` and `rewrite` write (AES-128/192/256, ZipCrypto, per-file
	protection), and `decrypt` reads what 7-Zip encrypts
- WinZip AES is the primary encrypted format to use for modern workflows
- ZipCrypto is included for compatibility with older ZIP consumers and tools
- plain ZIP archives remain readable through the same `ZipFile` API

This is not a claim of universal compatibility with every ZIP tool and every
feature combination. If interoperability matters for your environment, verify
the exact compression and encryption combinations you plan to ship.

## License

This project is licensed under the MIT License. Additional upstream licensing
and attribution files are included for the CPython- and pyzipper-derived
portions of the codebase:

- `LICENSE`
- `NOTICE`
- `licenses/CPYTHON-3.14.3.txt`
- `licenses/pyzipper-MIT.txt`
