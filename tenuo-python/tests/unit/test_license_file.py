"""Packages ship their own copy of ``LICENSE`` and ``NOTICE``; keep each
identical to the repository files so sdists, wheels, and crates carry the real
license. The Rust crates need in-crate copies because maturin rejects a
``license-file`` outside the crate directory when it builds the Python sdist."""

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


# tenuo-core and tenuo-wasm are published crates; tenuo-core is also a path
# dependency packed into the Python sdist by maturin.
CRATE_DIRS = ["tenuo-core", "tenuo-wasm"]
REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.skipif(not REPO_LICENSE.exists(), reason="not running from a repository checkout")
@pytest.mark.parametrize("crate", CRATE_DIRS)
@pytest.mark.parametrize("name", ["LICENSE", "NOTICE"])
def test_crate_legal_files_match_repo(crate: str, name: str) -> None:
    copy = REPO_ROOT / crate / name
    assert copy.exists(), f"{crate}/{name} is missing; copy the root {name} into the crate"
    assert copy.read_bytes() == (REPO_ROOT / name).read_bytes(), (
        f"{crate}/{name} differs from the repository {name}; copy the root file over it"
    )


@pytest.mark.skipif(not REPO_LICENSE.exists(), reason="not running from a repository checkout")
@pytest.mark.parametrize("crate", CRATE_DIRS)
def test_crate_license_file_stays_inside_crate(crate: str) -> None:
    manifest = (REPO_ROOT / crate / "Cargo.toml").read_text(encoding="utf-8")
    assert 'license-file = "LICENSE"' in manifest, (
        f"{crate}/Cargo.toml must use license-file = \"LICENSE\" (maturin rejects paths outside the crate)"
    )
