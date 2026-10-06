"""Linux subprocess fixture: resource limits apply before importing the parser."""

from __future__ import annotations

import argparse
import resource
from pathlib import Path


class WorkerArguments(argparse.Namespace):
    archive: Path = Path()
    destination: Path = Path()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args(namespace=WorkerArguments())
    resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 << 20, 2 << 20))

    from zipctl import (
        ArchiveLimits,
        ArchiveResourceLimitError,
        BadZipFile,
        ExtractionError,
        ExtractPolicy,
        ZipFile,
    )

    try:
        with ZipFile(
            args.archive,
            limits=ArchiveLimits(
                max_entries=100,
                max_directory_bytes=65536,
                max_metadata_bytes=8192,
                max_lzma_dictionary_bytes=1 << 20,
                max_zstd_window_bytes=1 << 20,
            ),
        ) as archive:
            archive.safe_extractall(
                args.destination,
                policy=ExtractPolicy(
                    max_member_size=1 << 20,
                    max_total_uncompressed_size=2 << 20,
                    max_compression_ratio=100,
                ),
            )
    except ExtractionError as exc:
        print(*(violation.message for violation in exc.result.violations), sep="\n")
        return
    except (ArchiveResourceLimitError, BadZipFile) as exc:
        print(exc)
        return
    raise SystemExit("hostile fixture unexpectedly accepted")


if __name__ == "__main__":
    main()
