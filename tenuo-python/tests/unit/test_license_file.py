"""The Python distribution ships ``tenuo-python/LICENSE``; keep it identical
to the repository ``LICENSE`` so sdists and wheels carry the real license."""

from __future__ import annotations

from pathlib import Path

import pytest

PACKAGE_LICENSE = Path(__file__).resolve().parents[2] / "LICENSE"
REPO_LICENSE = Path(__file__).resolve().parents[3] / "LICENSE"


@pytest.mark.skipif(not REPO_LICENSE.exists(), reason="not running from a repository checkout")
def test_package_license_matches_repo_license() -> None:
    assert PACKAGE_LICENSE.read_bytes() == REPO_LICENSE.read_bytes(), (
        "tenuo-python/LICENSE differs from the repository LICENSE; copy the root file over it"
    )
