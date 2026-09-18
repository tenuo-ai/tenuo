import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.validate_agent_skills import (
    INTEGRATION_SKILL,
    LINK_RE,
    ROOT,
    SKILLS,
    behavioral_eval_fingerprint,
    check_release_drift,
    markdown_link_destination,
    parse_frontmatter,
    repository_file_exists,
    repository_path_for_url,
    validate_release_contract,
    validate_links,
    validate_no_api_fences,
    validate_behavioral_eval_result,
    VERSION_LITERAL_RE,
)


class FrontmatterTests(unittest.TestCase):
    def test_accepts_crlf(self) -> None:
        metadata, error = parse_frontmatter(
            "---\r\nname: example\r\ndescription: Useful skill.\r\n---\r\n# Example\r\n"
        )
        self.assertIsNone(error)
        self.assertEqual(
            metadata, {"name": "example", "description": "Useful skill."}
        )

    def test_rejects_block_scalar_marker_as_description(self) -> None:
        metadata, error = parse_frontmatter(
            "---\nname: example\ndescription: >\n  Not a supported scalar.\n---\n"
        )
        self.assertIsNone(metadata)
        self.assertEqual(error, "description must be a non-empty single-line scalar")


class LinkTests(unittest.TestCase):
    def test_removes_optional_markdown_title(self) -> None:
        self.assertEqual(
            markdown_link_destination('references/python.md "Python reference"'),
            "references/python.md",
        )

    def test_accepts_angle_bracket_destination_with_title(self) -> None:
        self.assertEqual(
            markdown_link_destination('<references/a file.md> "A title"'),
            "references/a file.md",
        )

    def test_keeps_apostrophes_and_backslashes_in_destination(self) -> None:
        self.assertEqual(
            markdown_link_destination("references/don't-do-this.md"),
            "references/don't-do-this.md",
        )
        self.assertEqual(
            markdown_link_destination("references\\windows.md"),
            "references\\windows.md",
        )

    def test_rejects_destination_with_unterminated_title(self) -> None:
        self.assertIsNone(markdown_link_destination('references/a.md "open title'))

    def test_maps_tagged_repository_url_to_checkout(self) -> None:
        self.assertEqual(
            repository_path_for_url(
                "https://github.com/tenuo-ai/tenuo/blob/v0.3.0/tenuo-core/README.md#usage"
            ),
            ROOT / "tenuo-core/README.md",
        )

    def test_pinned_repository_file_exists_at_tag(self) -> None:
        self.assertTrue(repository_file_exists("v0.3.0", Path("tenuo-core/README.md")))

    def test_main_repository_link_is_rejected(self) -> None:
        errors = []
        validate_links(
            INTEGRATION_SKILL / "SKILL.md",
            "[Example](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-core/README.md)",
            INTEGRATION_SKILL,
            errors,
            required_repository_tag="v0.3.0",
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("not 'main'", errors[0])

    def test_other_skill_may_link_to_main_when_file_exists(self) -> None:
        errors = []
        validate_links(
            SKILLS / "tenuo-warrant" / "SKILL.md",
            "[Example](https://github.com/tenuo-ai/tenuo/blob/main/tenuo-core/README.md)",
            SKILLS / "tenuo-warrant",
            errors,
        )
        self.assertEqual(errors, [])

    def test_other_skill_main_link_must_name_checkout_file(self) -> None:
        errors = []
        validate_links(
            SKILLS / "tenuo-warrant" / "SKILL.md",
            "[Example](https://github.com/tenuo-ai/tenuo/blob/main/does/not/exist.md)",
            SKILLS / "tenuo-warrant",
            errors,
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("does not name a file in this checkout", errors[0])

    def test_missing_tag_explains_how_to_fetch_tags(self) -> None:
        errors = []
        available = validate_release_contract(
            {"repository_tag": "v9.9.9", "packages": []}, errors
        )
        self.assertFalse(available)
        self.assertEqual(len(errors), 1)
        self.assertIn("git fetch --tags --force", errors[0])

    def test_root_absolute_link_is_not_a_repository_file(self) -> None:
        self.assertIsNone(repository_path_for_url("/docs/authorization"))

    def test_root_absolute_link_is_not_resolved_on_the_host(self) -> None:
        with TemporaryDirectory() as directory:
            skill_dir = Path(directory)
            markdown = skill_dir / "SKILL.md"
            errors = []
            checked = validate_links(
                markdown, "[Site documentation](/docs/authorization)", skill_dir, errors
            )
        self.assertEqual(checked, 0)
        self.assertEqual(errors, [])

    def test_relative_link_with_title_resolves_inside_installed_skill(self) -> None:
        with TemporaryDirectory() as directory:
            skill_dir = Path(directory)
            references = skill_dir / "references"
            references.mkdir()
            (references / "python.md").write_text("# Python\n", encoding="utf-8")
            markdown = skill_dir / "SKILL.md"
            errors = []
            checked = validate_links(
                markdown,
                '[Python](references/python.md "Python reference")',
                skill_dir,
                errors,
            )
        self.assertEqual(checked, 1)
        self.assertEqual(errors, [])

    def test_relative_link_cannot_escape_copied_skill(self) -> None:
        with TemporaryDirectory(dir=ROOT) as directory:
            install_root = Path(directory)
            skill_dir = install_root / "tenuo-agent-authorization"
            skill_dir.mkdir()
            (install_root / "repository-example.py").write_text("", encoding="utf-8")
            markdown = skill_dir / "SKILL.md"
            errors = []
            checked = validate_links(
                markdown,
                "[Repository example](../repository-example.py)",
                skill_dir,
                errors,
            )
        self.assertEqual(checked, 0)
        self.assertEqual(len(errors), 1)
        self.assertIn("relative link escapes the installed skill", errors[0])


class ApiFenceTests(unittest.TestCase):
    def test_rejects_python_typescript_javascript_and_rust_fences(self) -> None:
        for language in ("python", "py", "typescript", "ts", "javascript", "js", "rust", "rs"):
            with self.subTest(language=language):
                errors = []
                validate_no_api_fences(
                    INTEGRATION_SKILL / "SKILL.md",
                    f"```{language}\nexample\n```\n",
                    errors,
                )
                self.assertEqual(len(errors), 1)

    def test_allows_non_api_fences(self) -> None:
        errors = []
        validate_no_api_fences(
            INTEGRATION_SKILL / "SKILL.md", "```text\nexample\n```\n", errors
        )
        self.assertEqual(errors, [])


class BehavioralEvalTests(unittest.TestCase):
    def test_fingerprint_is_stable_sha256_shape(self) -> None:
        fingerprint = behavioral_eval_fingerprint(["SKILL.md"])
        self.assertEqual(len(fingerprint), 64)
        int(fingerprint, 16)

    def test_fingerprint_only_covers_listed_inputs(self) -> None:
        self.assertNotEqual(
            behavioral_eval_fingerprint(["SKILL.md"]),
            behavioral_eval_fingerprint(["SKILL.md", "references/rust.md"]),
        )

    def test_stale_result_fails_with_rerun_guidance(self) -> None:
        errors = []
        validate_behavioral_eval_result(
            {
                "result": "pass",
                "evidence_kind": "fresh",
                "inputs": ["SKILL.md"],
                "skill_fingerprint": "0" * 64,
            },
            errors,
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("behavioral eval evidence is stale", errors[0])

    def test_inputs_must_include_entrypoint(self) -> None:
        errors = []
        validate_behavioral_eval_result(
            {
                "result": "pass",
                "evidence_kind": "fresh",
                "inputs": ["references/typescript.md"],
                "skill_fingerprint": behavioral_eval_fingerprint(["references/typescript.md"]),
            },
            errors,
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("must include SKILL.md", errors[0])

    def test_carried_forward_requires_review_rationale(self) -> None:
        errors = []
        validate_behavioral_eval_result(
            {
                "result": "pass",
                "evidence_kind": "carried_forward",
                "inputs": ["SKILL.md"],
                "skill_fingerprint": behavioral_eval_fingerprint(["SKILL.md"]),
            },
            errors,
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("carried_forward_review", errors[0])

    def test_language_result_must_cover_its_reference(self) -> None:
        errors = []
        validate_behavioral_eval_result(
            {
                "result": "pass",
                "language": "rust",
                "evidence_kind": "fresh",
                "inputs": ["SKILL.md"],
                "skill_fingerprint": behavioral_eval_fingerprint(["SKILL.md"]),
            },
            errors,
            "payment-boundary-result.rust.json",
            "rust",
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("references/rust.md", errors[0])

    def test_language_must_match_file_name(self) -> None:
        errors = []
        inputs = ["SKILL.md", "references/rust.md"]
        validate_behavioral_eval_result(
            {
                "result": "pass",
                "language": "python",
                "evidence_kind": "fresh",
                "inputs": inputs,
                "skill_fingerprint": behavioral_eval_fingerprint(inputs),
            },
            errors,
            "payment-boundary-result.rust.json",
            "rust",
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("language must be 'rust'", errors[0])

    def test_valid_result_returns_covered_inputs(self) -> None:
        errors = []
        inputs = ["SKILL.md", "references/rust.md"]
        covered = validate_behavioral_eval_result(
            {
                "result": "pass",
                "language": "rust",
                "evidence_kind": "fresh",
                "inputs": inputs,
                "skill_fingerprint": behavioral_eval_fingerprint(inputs),
            },
            errors,
            "payment-boundary-result.rust.json",
            "rust",
        )
        self.assertEqual(errors, [])
        self.assertEqual(covered, inputs)


class ReleaseDriftTests(unittest.TestCase):
    CONTRACT = {
        "repository_tag": "v0.3.0",
        "packages": [
            {
                "name": "Rust",
                "reference": "references/rust.md",
                "manifest": "tenuo-core/Cargo.toml",
                "format": "toml",
                "section": "package",
                "version": "0.0.0-never",
            }
        ],
    }

    def test_head_drift_warns_while_release_is_untagged(self) -> None:
        errors, warnings = [], []
        check_release_drift(
            self.CONTRACT, errors, warnings, require_current=False, tag_exists=lambda tag: False
        )
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("at HEAD declares", warnings[0])

    def test_head_drift_fails_once_release_tag_exists(self) -> None:
        errors, warnings = [], []
        check_release_drift(
            self.CONTRACT, errors, warnings, require_current=False, tag_exists=lambda tag: True
        )
        self.assertEqual(warnings, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("repin_agent_skill.py --tag v", errors[0])

    def test_forgotten_repin_is_detected_against_real_tags(self) -> None:
        # HEAD declares 0.3.0 and v0.3.0 exists, so pinning anything else is the
        # forgotten-re-pin state this check exists to catch.
        errors, warnings = [], []
        check_release_drift(self.CONTRACT, errors, warnings, require_current=False)
        self.assertEqual(len(errors), 1)
        self.assertIn("--tag v0.3.0", errors[0])

    def test_head_drift_fails_when_current_release_required(self) -> None:
        errors, warnings = [], []
        check_release_drift(
            self.CONTRACT, errors, warnings, require_current=True, tag_exists=lambda tag: False
        )
        self.assertEqual(warnings, [])
        self.assertEqual(len(errors), 1)


class ReleaseProseTests(unittest.TestCase):
    def test_detects_semver_in_prose_after_links_are_removed(self) -> None:
        text = (
            "For version 0.3.0-beta.0 use "
            "[the guide](https://example.test/blob/v0.3.0/README.md)."
        )
        prose_without_links = LINK_RE.sub("", text)
        match = VERSION_LITERAL_RE.search(prose_without_links)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(0), "0.3.0-beta.0")


if __name__ == "__main__":
    unittest.main()
