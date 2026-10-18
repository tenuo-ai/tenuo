# /// script
# requires-python = ">=3.12,<3.13"
# dependencies = ["tenuo==0.3.2"]
# ///
"""Focused receiver probes plus the documented real-framework commands."""
import asyncio
import subprocess
import sys
import time
import unittest
from pathlib import Path

EXAMPLES = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXAMPLES))
from common import NORMAL, Task, demonstrate
from tenuo import SigningKey, Warrant


class ReceiverTests(unittest.TestCase):
    def test_valid_then_same_tool_material_argument_denials(self):
        task = Task()
        self.assertEqual(task.pay(dict(NORMAL)), "paid")
        for field, value in [("bank_account", "attacker-bank"), ("invoice_id", "INV-999"), ("amount_cents", 40_000)]:
            with self.subTest(field=field), self.assertRaisesRegex(Exception, "[Cc]onstraint"):
                task.pay({**NORMAL, field: value})
            self.assertEqual(task.service.effect_count, 1)

    def test_missing_parent_is_not_repaired_by_trusting_worker(self):
        task = Task()
        with self.assertRaises(Exception):
            task.service.pay_invoice(NORMAL, task.chain[-1:], task.proof(NORMAL))
        self.assertEqual(task.service.effect_count, 0)

    def test_untrusted_root(self):
        task, other = Task(), Task()
        with self.assertRaises(Exception):
            task.service.pay_invoice(NORMAL, other.chain, other.proof(NORMAL))
        self.assertEqual(task.service.effect_count, 0)

    def test_wrong_holder_signs_same_challenge(self):
        task = Task()
        leaf = Warrant.from_base64(task.chain[-1])
        wrong_proof = leaf.sign(SigningKey.generate(), "pay_invoice", NORMAL, int(time.time()))
        with self.assertRaises(Exception):
            task.service.pay_invoice(NORMAL, task.chain, wrong_proof)
        self.assertEqual(task.service.effect_count, 0)

    def test_changed_arguments_after_signing(self):
        task = Task()
        # Amount remains inside authority, so this specifically exercises PoP.
        with self.assertRaises(Exception):
            task.service.pay_invoice({**NORMAL, "amount_cents": 19_999}, task.chain, task.proof(NORMAL))
        self.assertEqual(task.service.effect_count, 0)

    def test_receiver_rejects_coercive_types(self):
        task = Task()
        for amount in [True, "20000", 20_000.0]:
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                task.pay({**NORMAL, "amount_cents": amount})
        self.assertEqual(task.service.effect_count, 0)

    def test_startup_error_is_not_accepted_as_denial(self):
        async def broken(_):
            raise RuntimeError("constraint setup unavailable")
        with self.assertRaisesRegex(RuntimeError, "constraint setup unavailable"):
            asyncio.run(demonstrate(broken, lambda: 0))


class FrameworkCommands(unittest.TestCase):
    def test_real_dispatch_commands(self):
        for script in ["openai_agents.py", "langgraph_tools.py", "temporal.py", "mcp_stdio.py", "mcp2_stdio.py"]:
            with self.subTest(script=script):
                result = subprocess.run(["uv", "run", "--no-project", str(EXAMPLES / script)],
                    capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout.count("ALLOWED "), 1, result.stdout)
                self.assertEqual(result.stdout.count("DENIED  "), 3, result.stdout)
                self.assertEqual(result.stdout.count("effects=0"), 3, result.stdout)
                self.assertIn("Development only", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
