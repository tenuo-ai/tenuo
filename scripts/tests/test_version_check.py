import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

MAKEFILE = Path(__file__).resolve().parents[2] / "Makefile"


def write_tree(root: Path, init_line: str) -> None:
    files = {
        "tenuo-python/pyproject.toml": 'version = "1.2.3"\n',
        "tenuo-python/Cargo.toml": 'version = "1.2.3"\n',
        "tenuo-python/tenuo/__init__.py": f"{init_line}\n",
        "tenuo-core/Cargo.toml": 'version = "1.2.3"\n',
        "tenuo-wasm/Cargo.toml": 'version = "1.2.3"\n',
        "tenuo-ts/packages/core/package.json": json.dumps({"version": "1.2.3-beta.0"}),
        "tenuo-ts/packages/mcp/package.json": json.dumps({"version": "1.2.3-beta.0"}),
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (root / "tenuo-ts/examples").mkdir()


def version_check(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["make", "-s", "-f", str(MAKEFILE), "version-check"],
        cwd=root,
        capture_output=True,
        text=True,
    )


class PythonDunderVersionTests(unittest.TestCase):
    def run_check(self, init_line: str) -> subprocess.CompletedProcess:
        with TemporaryDirectory() as tmp:
            write_tree(Path(tmp), init_line)
            return version_check(Path(tmp))

    def test_passes_when_in_sync(self) -> None:
        result = self.run_check('__version__ = "1.2.3"')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fails_on_stale_value(self) -> None:
        result = self.run_check('__version__ = "1.2.2"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tenuo-python/tenuo/__init__.py: 1.2.2", result.stdout)

    def test_fails_when_missing(self) -> None:
        result = self.run_check("VERSION = None")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tenuo-python/tenuo/__init__.py:", result.stdout)


if __name__ == "__main__":
    unittest.main()
