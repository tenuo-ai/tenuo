"""Exercise the inventory scanners on source files, not just their regexes."""

import importlib.util
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
