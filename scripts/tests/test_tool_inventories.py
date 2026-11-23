"""Exercise the inventory scanners on source files, not just their regexes."""

import importlib.util
import shutil
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


SCRIPTS = Path(__file__).resolve().parents[2] / "skills/tenuo-agent-authorization/scripts"


def load_scanner(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ToolInventoryTests(unittest.TestCase):
    def test_rust_attributes_survive_comment_filter(self):
        for name in ("inspect_mcp_project", "inspect_native_tools"):
            with self.subTest(scanner=name), TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "tools.rs").write_text(
                    "#[tool]\nfn lookup() {}\n#[test]\nfn rejects_missing() {}\n"
                    "#[tokio::test]\nasync fn rejects_wrong_holder() {}\n"
                    "// #[test]\n// #[tool]\n/* #[test] */\n",
                    encoding="utf-8",
                )
                scanner = load_scanner(name)
                findings = scanner.inspect(root)
                tests = [f for f in findings if f.kind == "test"]
                self.assertEqual([f.line for f in tests], [3, 5])
                if name == "inspect_mcp_project":
                    endpoints = [f for f in findings if f.kind == "mcp_server"]
                    self.assertEqual([f.line for f in endpoints], [1])
                summary = scanner.summarize(findings, 1)
                self.assertEqual(summary["counts"]["test"], 2)
                self.assertEqual(summary["truncated"]["test"], 1)

    def test_candidate_symbols_do_not_certify_a_boundary(self):
        for name in ("inspect_mcp_project", "inspect_native_tools"):
            with self.subTest(scanner=name), TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "agent.py").write_text(
                    "from tenuo.openai import guard_agent\n"
                    "server = TenuoServerMiddleware(verifier)\n"
                    "worker = TenuoWorkerInterceptor(config)\n"
                    "refund_order(order_id)\n"
                )
                scanner = load_scanner(name)
                summary = scanner.summarize(scanner.inspect(root), 8)
                self.assertFalse(summary["certified"])
                candidates = summary["candidate_boundaries"]
                self.assertEqual(candidates[0]["path"], "agent.py")
                self.assertTrue(candidates[0]["effects"])
                self.assertIn("Unverified", candidates[0]["possible_bypass"])
                self.assertTrue(candidates[0]["existing_interception"])

    def test_candidate_evidence_shares_the_per_kind_budget(self):
        for name in ("inspect_mcp_project", "inspect_native_tools"):
            with self.subTest(scanner=name), TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "agent.py").write_text("subprocess.run(cmd)\n" * 50)
                scanner = load_scanner(name)
                summary = scanner.summarize(scanner.inspect(root), 1)
                self.assertEqual(summary["counts"]["effect"], 50)
                self.assertEqual(summary["truncated"]["effect"], 49)
                nested = [e for c in summary["candidate_boundaries"] for e in c["effects"]]
                self.assertEqual(len(nested), 1)

    def test_installed_skill_and_named_virtualenv_are_not_application_evidence(self):
        for name in ("inspect_mcp_project", "inspect_native_tools"):
            with self.subTest(scanner=name), TemporaryDirectory() as directory:
                root = Path(directory)
                installed = root / ".claude/skills/tenuo-agent-authorization"
                (installed / "scripts").mkdir(parents=True)
                shutil.copy(SCRIPTS / f"{name}.py", installed / "scripts" / f"{name}.py")
                (installed / "example.py").write_text("MCPVerifier()\nrefund_order()\n")
                environment = root / ".venv-mcp2"
                environment.mkdir()
                (environment / "pyvenv.cfg").write_text("home = /some/python\n")
                (environment / "dependency.py").write_text("MCPVerifier()\nrefund_order()\n")
                # Other configuration is still project evidence.
                (root / ".claude/settings.json").write_text('{"command": "refund_order()"}')
                (root / "agent.py").write_text("refund_order()\n")
                spec = importlib.util.spec_from_file_location(name, installed / "scripts" / f"{name}.py")
                scanner = importlib.util.module_from_spec(spec)
                sys.modules[name] = scanner
                spec.loader.exec_module(scanner)
                paths = {finding.path for finding in scanner.inspect(root)}
                self.assertEqual(paths, {"agent.py", ".claude/settings.json"})

    def test_external_symlink_does_not_invent_target_effects(self):
        for name in ("inspect_mcp_project", "inspect_native_tools"):
            with self.subTest(scanner=name), TemporaryDirectory() as directory:
                root = Path(directory) / "project"
                root.mkdir()
                external = Path(directory) / "external.py"
                external.write_text("refund_order()\n")
                (root / "external.py").symlink_to(external)
                self.assertEqual(load_scanner(name).inspect(root), [])

    def test_python_hash_comments_still_ignored(self):
        for name in ("inspect_mcp_project", "inspect_native_tools"):
            with self.subTest(scanner=name), TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "tools.py").write_text(
                    "# pytest assert False\n# Authorizer()\nassert allowed\n",
                    encoding="utf-8",
                )
                findings = load_scanner(name).inspect(root)
                self.assertEqual([(f.kind, f.line) for f in findings], [("test", 3)])


if __name__ == "__main__":
    unittest.main()
