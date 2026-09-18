import json
import unittest
from pathlib import Path

from scripts.repin_agent_skill import (
    RepinError,
    default_review,
    repin,
    rewrite_links,
    updated_contract,
)
from scripts.validate_agent_skills import RELEASE_CONTRACT


class RewriteLinkTests(unittest.TestCase):
    def test_retargets_only_this_repository_blob_links(self) -> None:
        text = (
            "[a](https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-core/README.md) "
            "[b](https://github.com/other/repo/blob/v0.3.0/README.md) v0.3.0"
        )
        self.assertEqual(
            rewrite_links(text, "v0.3.0", "v0.4.0"),
            "[a](https://github.com/tenuo-ai/tenuo/blob/v0.4.0/tenuo-core/README.md) "
            "[b](https://github.com/other/repo/blob/v0.3.0/README.md) v0.3.0",
        )


class ContractTests(unittest.TestCase):
    def test_reads_versions_from_manifests_at_tag(self) -> None:
        contract = {
            "repository_tag": "v0.3.0",
            "packages": [
                {"name": "Rust", "manifest": "tenuo-core/Cargo.toml", "format": "toml",
                 "section": "package", "version": "0.0.0"},
                {"name": "TS", "manifest": "tenuo-ts/packages/core/package.json",
                 "format": "json", "version": "0.0.0"},
            ],
        }
        texts = {
            "tenuo-core/Cargo.toml": '[package]\nname = "tenuo"\nversion = "0.4.0"\n',
            "tenuo-ts/packages/core/package.json": '{"version": "0.4.0-beta.1"}',
        }
        updated = updated_contract(
            contract, "v0.4.0", file_text=lambda tag, path: texts.get(path.as_posix())
        )
        self.assertEqual(updated["repository_tag"], "v0.4.0")
        self.assertEqual([p["version"] for p in updated["packages"]], ["0.4.0", "0.4.0-beta.1"])
        self.assertEqual(contract["repository_tag"], "v0.3.0", "input must not be mutated")

    def test_missing_manifest_at_tag_is_an_error(self) -> None:
        contract = {"repository_tag": "v0.3.0", "packages": [{"manifest": "gone.toml"}]}
        with self.assertRaises(RepinError):
            updated_contract(contract, "v0.4.0", file_text=lambda tag, path: None)

    def test_current_contract_round_trips_against_its_own_tag(self) -> None:
        contract = json.loads(RELEASE_CONTRACT.read_text(encoding="utf-8"))
        updated = updated_contract(contract, contract["repository_tag"])
        self.assertEqual(updated, contract)


class RepinTests(unittest.TestCase):
    def test_already_pinned_tag_is_a_noop(self) -> None:
        contract = json.loads(RELEASE_CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(repin(contract["repository_tag"], dry_run=True), [])

    def test_rejects_non_semver_and_unknown_tags(self) -> None:
        with self.assertRaises(RepinError):
            repin("main", dry_run=True)
        with self.assertRaises(RepinError):
            repin("v9.9.9", dry_run=True)

    def test_dry_run_lists_contract_and_linked_references(self) -> None:
        changed = repin("v0.2.5", dry_run=True)
        names = {Path(p).name for p in changed}
        self.assertIn("release.json", names)
        self.assertIn("python.md", names)
        self.assertIn("rust.md", names)

    def test_default_review_names_both_tags(self) -> None:
        review = default_review("v0.3.0", "v0.4.0")
        self.assertIn("v0.3.0", review)
        self.assertIn("v0.4.0", review)


if __name__ == "__main__":
    unittest.main()
