"""The Python distribution ships ``tenuo-python/LICENSE``; keep it identical
to the repository ``LICENSE`` so sdists and wheels carry the real license."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

PACKAGE_LICENSE = Path(__file__).resolve().parents[2] / "LICENSE"
REPO_LICENSE = Path(__file__).resolve().parents[3] / "LICENSE"
PACKAGE_NOTICE = Path(__file__).resolve().parents[2] / "NOTICE"
REPO_NOTICE = Path(__file__).resolve().parents[3] / "NOTICE"
APACHE_2_LICENSE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"


@pytest.mark.skipif(not REPO_LICENSE.exists(), reason="not running from a repository checkout")
def test_package_license_matches_repo_license() -> None:
    repo_license = REPO_LICENSE.read_bytes()
    assert hashlib.sha256(repo_license).hexdigest() == APACHE_2_LICENSE_SHA256, (
        "the repository LICENSE is not the canonical Apache License 2.0 text"
    )
    assert PACKAGE_LICENSE.read_bytes() == repo_license, (
        "tenuo-python/LICENSE differs from the repository LICENSE; copy the root file over it"
    )


@pytest.mark.skipif(not REPO_NOTICE.exists(), reason="not running from a repository checkout")
def test_package_notice_matches_repo_notice() -> None:
    assert PACKAGE_NOTICE.read_bytes() == REPO_NOTICE.read_bytes(), (
        "tenuo-python/NOTICE differs from the repository NOTICE; copy the root file over it"
    )
