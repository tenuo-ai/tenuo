import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.validate_agent_skills import (
    INTEGRATION_SKILL,
    LINK_RE,
    ROOT,
    behavioral_eval_fingerprint,
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
        fingerprint = behavioral_eval_fingerprint()
        self.assertEqual(len(fingerprint), 64)
        int(fingerprint, 16)

    def test_stale_result_fails_with_rerun_guidance(self) -> None:
        errors = []
        validate_behavioral_eval_result(
            {"result": "pass", "skill_fingerprint": "0" * 64}, errors
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("behavioral eval evidence is stale", errors[0])


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
