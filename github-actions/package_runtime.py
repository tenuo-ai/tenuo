#!/usr/bin/env python3
"""Assemble the GitHub Action artifact by copying the Ubuntu tenuo wheel into vendor/.

v1 supports Ubuntu runners (manylinux). Building the wheel during CI is not
enough: install-runtime.mjs only loads wheels from vendor/ or TENUO_WHEEL.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

ACTION_ROOT = Path(__file__).resolve().parent
REPO_ROOT = ACTION_ROOT.parent


def ubuntu_wheels(paths: list[Path]) -> list[Path]:
    return [path for path in paths if "manylinux" in path.name or "linux_" in path.name]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wheel",
        type=Path,
        help="Source wheel. Default: the newest manylinux wheel under tenuo-python/target/wheels.",
    )
    args = parser.parse_args()
    if args.wheel:
        source = args.wheel
        if not source.is_file():
            print(f"wheel not found: {source}", file=sys.stderr)
            return 1
        if not ubuntu_wheels([source]):
            print(
                f"{source.name} is not an Ubuntu/manylinux wheel; v1 supports Ubuntu runners only",
                file=sys.stderr,
            )
            return 1
    else:
        built = sorted(REPO_ROOT.glob("tenuo-python/target/wheels/tenuo-*.whl"))
        matched = ubuntu_wheels(built)
        if not matched:
            print(
                "no Ubuntu/manylinux tenuo wheel in tenuo-python/target/wheels; "
                "run: (cd tenuo-python && maturin build --release) on Linux",
                file=sys.stderr,
            )
            return 1
        source = matched[-1]

    vendor = ACTION_ROOT / "vendor"
    vendor.mkdir(parents=True, exist_ok=True)
    for stale in vendor.glob("tenuo-*.whl"):
        stale.unlink()
    dest = vendor / source.name
    shutil.copy2(source, dest)
    print(dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
