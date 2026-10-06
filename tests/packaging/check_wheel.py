"""Install exactly one built wheel in an isolated environment, then test it."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


class WheelArguments(argparse.Namespace):
    wheel_dir: Path = Path()
    dependencies: str = "base"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument(
        "--dependencies", choices=("base", "all", "minimum"), required=True
    )
    args = parser.parse_args(namespace=WheelArguments())
    wheels = list(Path(args.wheel_dir).resolve().glob("zipctl-*.whl"))
    if len(wheels) != 1:
        parser.error(f"expected exactly one zipctl wheel, found {len(wheels)}")
    smoke = Path(__file__).with_name("test_installed.py").resolve()
    with tempfile.TemporaryDirectory(prefix="zipctl-wheel-") as directory:
        root = Path(directory)
        environment = root / "environment"
        python = environment / (
            "Scripts/python.exe" if os.name == "nt" else "bin/python"
        )
        subprocess.run(
            ["uv", "venv", "--python", sys.executable, str(environment)], check=True
        )
        requirement = str(wheels[0])
        if args.dependencies != "base":
            requirement += "[zstd,completion]"
        # The wheel itself is the direct requirement; lowest-direct would leave
        # its dependencies at their latest versions. Resolve the whole graph.
        resolution = "lowest" if args.dependencies == "minimum" else "highest"
        subprocess.run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(python),
                "--resolution",
                resolution,
                requirement,
            ],
            check=True,
        )
        subprocess.run(["uv", "pip", "check", "--python", str(python)], check=True)
        subprocess.run(
            [str(python), "-I", str(smoke)],
            cwd=root,
            env={**os.environ, "ZIPCTL_WHEEL_DEPENDENCIES": args.dependencies},
            check=True,
            timeout=120,
        )


if __name__ == "__main__":
    main()
