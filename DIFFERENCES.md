# Differences from the standard library's `zipfile`

`zipctl` keeps the top-level API of Python's `zipfile` (`ZipFile`, `ZipInfo`,
`open`, `read`, `write`, `writestr`, `extract`, `extractall`, `Path`, ...) so it
feels familiar. Below that surface it is deliberately stricter: an archive must
have exactly one interpretation, every byte of it must be accounted for, and
redundant fields must agree. Anything else is refused with `BadZipFile` (or a
`ValueError` for a mistake by the caller) rather than repaired or guessed at.

## Reading

| Situation | `zipfile` | `zipctl` |
| --- | --- | --- |
| Two members with the same name | Accepted; the last one wins | `BadZipFile: Duplicate name` |
| Bytes after the end-of-central-directory record | Ignored | `BadZipFile: Data after the end of the central directory` |
| Bytes before the archive (a self-extracting stub) | Accepted | Refused unless `ZipFile(..., allow_prepended_data=True)` / `--allow-prepended-data` |
| Bytes between entries, or before the first one | Ignored | `BadZipFile: Unaccounted bytes ...` (a stub before the first entry is accepted with `allow_prepended_data=True`; bytes before the central directory are refused on open, except an APK Signing Block, which mode `'a'` writes over) |
| Local header offset past the central directory, or shared by two entries | Fails on read | `BadZipFile: Bad offset for local file header` on open |
| Bytes after the end of a deflate, bzip2 or LZMA stream | Ignored | `BadZipFile: Data after the end of the compressed stream` |
| Entries whose data overlap | Warned about, or refused for some layouts | Always refused (`Overlapped entries`) |
| Data descriptor disagreeing with the central directory | Not read | Read and compared; a mismatch is refused |
| Local and central headers disagreeing (method, flags, sizes, CRC, Unicode path) | Partly checked | All checked |
| Entry counts in the end record disagreeing | Accepted | Refused |
| Duplicate ZIP64, AES or Unicode Path extra fields | Accepted | Refused |
| 1-3 trailing bytes after the last extra field (zipalign padding) | Accepted | Accepted (as 7-Zip does); a field that overruns the block is refused |
| WinZip AES 2 entry storing its real CRC instead of 0 | Accepted | Accepted if local and central agree; the CRC is not checked (the HMAC is) |
| Deflate stream that ends without its final block | Accepted | Refused as truncated |
| `\` in member names | A separator on Windows only | A separator on every platform |

## Writing

| Situation | `zipfile` | `zipctl` |
| --- | --- | --- |
| Writing a name that is already in the archive | `UserWarning` | `ValueError: Duplicate name` |
| `writestr(info, ...)` / `open(info, "w")` | Changes the caller's `ZipInfo` | Writes a copy; the caller's `ZipInfo` is untouched |
| Exception inside `with zf.open(name, "w")` | The truncated entry is committed | The entry is aborted |
| An entry ending past 2 GiB with `allowZip64=False` | `LargeZipFile` from `close()`; no central directory | `LargeZipFile` when the entry finishes; a seekable archive stays valid without it, while an unseekable stream cannot be finished (`close()` raises `ValueError`) |
| Setting `comment` to bytes holding an end of central directory record that ends with the comment | Written; the archive becomes ambiguous | `ValueError` |
| Mode `'a'` on a file that is not a valid archive | A new archive is appended after its bytes | Refused; only an empty or missing file starts a new archive |
| Exactly 65,535 entries | No ZIP64 end record | ZIP64 end record (0xFFFF means "see ZIP64") |
| `compresslevel` outside the method's range | Passed to the codec | `ValueError` |
| Unknown `encryption=` value (including `""`) | Not applicable | `ValueError` from the constructor, the setter or the call |
| Year outside 1980-2107 | `struct.error` (after 2107) | `ValueError` |
| Exception leaving `with ZipFile(...)` while an entry is open | `ValueError` from `close()`; no central directory | The entry is aborted and the archive closed normally |

Appending (mode `'a'`) writes new entries over the old central directory and
writes a new one on close, as `zipfile` does. A crash, or a failed `close()`
(a full disk, say), before that leaves the archive unreadable: append to a copy
when the original matters. The `zipctl create --append` command does that.

## Extraction

`extract()` and `extractall()` keep their signatures but always run under an
`ExtractPolicy` (by default `ExtractPolicy()`: no traversal, absolute paths,
symlinks, special files or overwrites; finite size, count, ratio and path
length/depth limits). A directory member whose target is already a directory
(not a symlink) merges into it rather than counting as an overwrite, and a
member whose path runs through a symlink or a file is refused before anything
is written. Pass `policy=` to relax it. Every member is assessed before
anything is written, so an error finding anywhere refuses the whole archive and
nothing is created. `safe_extract()` / `safe_extractall()` do the same and
return the structured result.

Some failures can only be found while writing: data that does not decompress,
a size that turns out to be a lie, or a member written through a symlink the
archive itself created. Members extracted before such a failure stay on disk,
along with any directories created for them; the failing member leaves no
partial file.

Two names that differ only in case or Unicode normalisation (`a.txt` and
`A.txt`) count as the same target, because APFS, NTFS and casefolded ext4 store
them as one file. Pass `reject_duplicate_targets=False` to extract both on a
case-sensitive filesystem.

On Windows, where there is no `O_NOFOLLOW` or `dir_fd`, parent directories are
checked for links and junctions by path. That protects against what the
archive contains, but not against another local user who swaps a directory in
the destination for a junction while extraction runs. Extract into a directory
only you can write to.

`inspect()` and `assess()` default to the same `ExtractPolicy()`.

## Removed compatibility surface

- `ZipFile.filelist` is a tuple and `NameToInfo` a read-only mapping (neither
  copies nor can be assigned); `infolist()` returns a list copy; `start_dir` is read-only; the `debug` attribute is gone.
- pyzipper's `ZipInfo.use_datadescripter` and CPython's `_compresslevel` are not
  provided; use `use_data_descriptor` and `compress_level`. pyzipper's
  `encode_datadescripter()` and `datadescripter()` have no counterpart: `ZipInfo`
  does not encode records, except `FileHeader()`.
- `Path` wraps the archive in `CompleteDirs` instead of changing its class.
- `zipctl extract --no-policy` is gone; pass a permissive `--policy-json`.

## What WinZip AES authenticates

The WinZip AES HMAC covers a member's ciphertext only. Its name, compression
method, sizes, timestamps and attributes are not authenticated: someone who can
modify the archive can rename an intact encrypted member, or mark it as a
symlink, without the HMAC failing. `verify_integrity()` and
`zipctl check-password --full` confirm the data, not the archive as a whole.
