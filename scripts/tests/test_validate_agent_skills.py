import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.validate_agent_skills import (
    ROOT,
    markdown_link_destination,
    parse_frontmatter,
    repository_path_for_url,
    validate_links,
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

    def test_maps_canonical_repository_url_to_checkout(self) -> None:
        self.assertEqual(
            repository_path_for_url(
                "https://github.com/tenuo-ai/tenuo/blob/main/tenuo-core/README.md#usage"
            ),
            ROOT / "tenuo-core/README.md",
        )

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


if __name__ == "__main__":
    unittest.main()
