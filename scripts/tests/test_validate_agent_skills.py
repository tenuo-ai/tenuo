import json
import unittest
from unittest.mock import patch
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.validate_agent_skills import (
    INTEGRATION_SKILL,
    LINK_RE,
    ROOT,
    SKILLS,
    behavioral_eval_fingerprint,
    load_behavioral_eval_results,
    main,
    check_release_drift,
    manifest_version,
    markdown_link_destination,
    parse_frontmatter,
    repository_file_exists,
    repository_path_for_url,
    repository_tag_exists,
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

    def test_stale_result_warns_without_rewriting_evidence(self) -> None:
        errors, warnings = [], []
        validate_behavioral_eval_result(
            {
                "result": "pass",
                "evidence_kind": "fresh",
                "inputs": ["SKILL.md"],
                "skill_fingerprint": "0" * 64,
            },
            errors,
            warnings=warnings,
        )
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("behavioral eval evidence is stale", warnings[0])

    def result(self, **updates):
        inputs = ["SKILL.md", "references/rust.md"]
        return dict({
            "result": "fail", "language": "rust", "evidence_kind": "fresh",
            "inputs": inputs, "skill_fingerprint": behavioral_eval_fingerprint(inputs),
            "evidence": {"critical_items": "passed", "required_reporting": "failed",
                         "notes": "Known reporting deficiency."},
        }, **updates)

    def test_failed_result_is_advisory_even_for_critical_failure(self) -> None:
        for critical in ("passed", "failed"):
            with self.subTest(critical=critical):
                errors, warnings = [], []
                result = self.result(evidence={"critical_items": critical})
                validate_behavioral_eval_result(result, errors, warnings=warnings)
                self.assertEqual(errors, [])
                self.assertIn("review findings", warnings[0])
                self.assertEqual(result["result"], "fail")

    def test_invalid_evidence_still_fails(self) -> None:
        for updates in (
            {"result": "unknown"}, {"result": None},
            {"evidence_kind": []},
            {"skill_fingerprint": "not-a-hash"},
            {"evidence": []}, {"evidence": {"critical_items": "maybe"}},
            {"evidence": {"required_reporting": "maybe"}},
            {"result": "pass"},  # Contradicts failed reporting.
            {"inputs": ["SKILL.md", "../README.md"]},
            {"inputs": ["SKILL.md", "/etc/passwd"]},
        ):
            with self.subTest(updates=updates):
                errors = []
                validate_behavioral_eval_result(self.result(**updates), errors)
                self.assertTrue(errors)

    def test_report_distinguishes_results_and_freshness_and_preserves_files(self) -> None:
        with TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "payment-boundary-result.rust.json"
            original = json.dumps(self.result(skill_fingerprint="0" * 64))
            path.write_text(original)
            errors, notices, warnings = [], [], []
            with patch("scripts.validate_agent_skills.BEHAVIORAL_EVAL_DIR", Path(directory)):
                report = load_behavioral_eval_results(errors, notices, warnings)
            self.assertEqual(errors, [])
            self.assertIn("| rust | fail | passed | failed | stale | fresh |", report)
            self.assertIn("Known reporting deficiency", report)
            self.assertEqual(len([w for w in warnings if path.name in w and Path(directory).name in w]), 2)
            self.assertEqual(path.read_text(), original)

    def test_missing_evidence_is_advisory_but_malformed_json_fails(self) -> None:
        with TemporaryDirectory(dir=ROOT) as directory:
            with patch("scripts.validate_agent_skills.BEHAVIORAL_EVAL_DIR", Path(directory)):
                errors, notices, warnings = [], [], []
                load_behavioral_eval_results(errors, notices, warnings)
                self.assertEqual(errors, [])
                self.assertTrue(warnings)
                path = Path(directory) / "payment-boundary-result.rust.json"
                path.write_text("{broken")
                report = load_behavioral_eval_results(errors, [], [])
                self.assertTrue(errors)
                self.assertIn("invalid eval result", report)

    def test_cli_succeeds_with_failed_evidence_and_writes_summary(self) -> None:
        with TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "payment-boundary-result.rust.json").write_text(json.dumps(self.result()))
            with patch("scripts.validate_agent_skills.BEHAVIORAL_EVAL_DIR", root), \
                 patch("scripts.validate_agent_skills._emit"):
                self.assertEqual(main(["--summary", str(root / "summary.md")]), 0)
            self.assertIn("| rust | fail | passed | failed | current |", (root / "summary.md").read_text())

    def test_cli_still_fails_on_malformed_evidence(self) -> None:
        with TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            (root / "payment-boundary-result.rust.json").write_text("[]")
            with patch("scripts.validate_agent_skills.BEHAVIORAL_EVAL_DIR", root), \
                 patch("scripts.validate_agent_skills._emit"):
                self.assertEqual(main([]), 1)

    def test_other_skill_evidence_is_fingerprinted_against_its_own_directory(self) -> None:
        with TemporaryDirectory() as tmp:
            skill = Path(tmp) / "tenuo-example"
            skill.mkdir()
            (skill / "SKILL.md").write_text("---\nname: tenuo-example\ndescription: x\n---\n")
            inputs = ["SKILL.md"]
            result = {
                "language": "python",
                "inputs": inputs,
                "evidence_kind": "fresh",
                "result": "pass",
                "skill_fingerprint": behavioral_eval_fingerprint(inputs, skill),
            }
            errors: list[str] = []
            covered = validate_behavioral_eval_result(
                result, errors, "x-result.python.json", "python",
                skill_dir=skill, scenario="x-eval.md",
            )
        # No references/python.md in this skill, so the language reference is not required.
        self.assertEqual(errors, [])
        self.assertEqual(covered, ["SKILL.md"])

    def test_other_skill_stale_evidence_names_its_scenario(self) -> None:
        with TemporaryDirectory() as tmp:
            skill = Path(tmp) / "tenuo-example"
            skill.mkdir()
            (skill / "SKILL.md").write_text("---\nname: tenuo-example\ndescription: x\n---\n")
            result = {
                "language": "python", "inputs": ["SKILL.md"], "evidence_kind": "fresh",
                "result": "pass", "skill_fingerprint": "0" * 64,
            }
            errors: list[str] = []
            warnings: list[str] = []
            validate_behavioral_eval_result(
                result, errors, "x-result.python.json", "python",
                warnings=warnings, skill_dir=skill, scenario="x-eval.md",
            )
        self.assertEqual(errors, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("Review x-eval.md", warnings[0])

    def test_multi_skill_report_keeps_failed_and_stale_results_advisory(self) -> None:
        with TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            skills, evaluations = root / "skills", root / "evaluations"
            originals = {}
            for name, outcome in (("first", "fail"), ("second", "pass")):
                skill = skills / name
                skill.mkdir(parents=True)
                (skill / "SKILL.md").write_text(f"# {name}\n")
                evidence_dir = evaluations / name
                evidence_dir.mkdir(parents=True)
                result = {
                    "result": outcome, "language": "python", "evidence_kind": "fresh",
                    "inputs": ["SKILL.md"],
                    "skill_fingerprint": behavioral_eval_fingerprint(["SKILL.md"], skill),
                }
                path = evidence_dir / "example-result.python.json"
                originals[path] = json.dumps(result)
                path.write_text(originals[path])
                if name == "second":
                    (skill / "SKILL.md").write_text("# Changed after evaluation\n")
            errors, notices, warnings = [], [], []
            with patch("scripts.validate_agent_skills.SKILLS", skills), \
                 patch("scripts.validate_agent_skills.BEHAVIORAL_EVAL_ROOT", evaluations):
                report = load_behavioral_eval_results(errors, notices, warnings)
            self.assertEqual(errors, [])
            self.assertEqual(len(warnings), 2)
            self.assertIn("| first | example-eval.md | python | fail | not recorded | not recorded | current |", report)
            self.assertIn("| second | example-eval.md | python | pass | not recorded | not recorded | stale |", report)
            for path, original in originals.items():
                self.assertEqual(path.read_text(), original)

    def test_other_skill_cannot_read_outside_its_directory(self) -> None:
        with TemporaryDirectory() as directory:
            skill = Path(directory) / "skill"
            skill.mkdir()
            (skill / "SKILL.md").write_text("# Example\n")
            (Path(directory) / "outside.md").write_text("outside")
            (skill / "linked.md").symlink_to(Path(directory) / "outside.md")
            for item in ("../outside.md", "linked.md"):
                with self.subTest(item=item):
                    result = self.result(inputs=["SKILL.md", item])
                    errors = []
                    validate_behavioral_eval_result(result, errors, skill_dir=skill)
                    self.assertIn("inputs must stay inside", errors[0])

    def test_other_skill_requires_language_reference_when_it_ships_one(self) -> None:
        with TemporaryDirectory() as directory:
            skill = Path(directory)
            (skill / "SKILL.md").write_text("# Example\n")
            (skill / "references").mkdir()
            (skill / "references/rust.md").write_text("# Rust\n")
            result = self.result(inputs=["SKILL.md"], skill_fingerprint=behavioral_eval_fingerprint(["SKILL.md"], skill))
            errors = []
            validate_behavioral_eval_result(result, errors, language="rust", skill_dir=skill)
            self.assertIn("must include references/rust.md", errors[0])

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
        # Integration check against the real manifest and the real tags. The
        # contract pins a version HEAD never declares, so drift is certain;
        # which side it lands on depends on whether HEAD's version is tagged.
        # On a release-bump PR the tag does not exist yet and drift must be a
        # warning; once the release is tagged and the skill was not re-pinned,
        # it must be the error this check exists to catch.
        package = self.CONTRACT["packages"][0]
        head_version = manifest_version(
            (ROOT / package["manifest"]).read_text(encoding="utf-8"), package
        )
        self.assertIsNotNone(head_version)
        head_tag = f"v{head_version}"

        errors, warnings = [], []
        check_release_drift(self.CONTRACT, errors, warnings, require_current=False)
        if repository_tag_exists(head_tag):
            self.assertEqual(warnings, [])
            self.assertEqual(len(errors), 1)
            self.assertIn(f"--tag {head_tag}", errors[0])
        else:
            self.assertEqual(errors, [])
            self.assertEqual(len(warnings), 1)
            self.assertIn(f"at HEAD declares {head_version!r}", warnings[0])

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
