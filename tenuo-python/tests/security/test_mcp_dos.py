"""
PoC for MCP Configuration DoS Vulnerability.

This script attempts to trigger resource exhaustion or limits check
by loading a maliciously large configuration file.
"""

import os
import tempfile
import unittest
from unittest.mock import patch

import tenuo.mcp.client
from tenuo.mcp.client import SecureMCPClient


class TestMcpDos(unittest.IsolatedAsyncioTestCase):
    async def test_large_config_loading(self):
        """Test if client handles massively large config file."""

        # Patch MCP_AVAILABLE to bypass import check
        with patch.object(tenuo.mcp.client, "MCP_AVAILABLE", True):
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
                f.write('version: "1"\ntools:\n')
                # Create 1 tool with 150 constraints (exceeds 100 limit)
                f.write('  vulnerable_tool:\n    description: "A tool to trigger DoS"\n    constraints:\n')
                for i in range(150):
                    f.write(f"      param_{i}:\n        from: body\n        path: param_{i}\n")

                config_path = f.name

            try:
                print(f"Attempting to load config with 150 constraints from {config_path}...")
                # We expect a ConfigurationError from Rust limits
                try:
                    # Mocking connect/close because we don't have a server,
                    # but we want __init__ to run which loads config
                    _client = SecureMCPClient("python", ["dummy.py"], config_path=config_path)
                    print("FAILURE: Client initialized without error!")
                    self.fail("Client should have raised ConfigurationError due to limits")
                except Exception as e:
                    print(f"SUCCESS: Caught expected exception: {e}")
                    # Optional: Verify it's the right message
                    if "Too many constraints" in str(e) or "configuration error" in str(e).lower():
                        print("Verified limit enforcement.")
                    else:
                        print(f"WARNING: Unexpected error message: {e}")
                        raise e

            finally:
                if os.path.exists(config_path):
                    os.unlink(config_path)


if __name__ == "__main__":
    unittest.main()
