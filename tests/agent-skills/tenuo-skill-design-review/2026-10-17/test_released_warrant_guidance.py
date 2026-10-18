from pathlib import Path
import hashlib
import importlib.metadata
import json
import re
import time
import unittest
from tenuo import Authorizer, Exact, Range, SigningKey, Warrant

SKILL = Path(__file__).resolve().parents[4] / 'skills' / 'tenuo-warrant' / 'SKILL.md'

class ReleasedWarrantExample(unittest.TestCase):
    def setUp(self):
        text = SKILL.read_text()
        section = text.split('**Open-source Python example:**', 1)[1]
        source = re.search(r'```python\n(.*?)\n```', section, re.S).group(1)
        self.artifacts = {}
        exec(compile(source, str(SKILL), 'exec'), self.artifacts)
        self.parent = self.artifacts['parent']
        self.child = self.artifacts['child']
        self.worker = self.artifacts['worker']
        self.issuer = self.artifacts['issuer']
        self.agent = self.artifacts['agent']
        self.args = dict(invoice_id='inv-123', bank_account='approved-bank', amount_cents=20000)

    def verify(self, args, *, chain=None, signer=None, roots=None):
        proof = self.child.sign(signer or self.worker, 'pay_invoice', args, int(time.time()))
        auth = Authorizer(trusted_roots=roots or [self.issuer.public_key], clock_tolerance_secs=0)
        return auth.check_chain(chain or [self.parent, self.child], 'pay_invoice', args, proof)

    def test_actual_markdown_snippet_mints_roundtrippable_terminal_child(self):
        self.assertEqual(self.parent.depth, 0)
        self.assertEqual(self.parent.max_depth, 64)
        self.assertEqual(self.child.depth, 1)
        self.assertTrue(self.child.is_terminal())
        self.assertEqual([Warrant.from_base64(t).id for t in self.artifacts['chain']], [self.parent.id, self.child.id])
        self.verify(self.args)

    def test_child_amount_ceiling_even_when_real_holder_signs(self):
        with self.assertRaises(Exception):
            self.verify({**self.args, 'amount_cents': 40000})
        # Positive control: this same amount is allowed by the actual parent.
        auth = Authorizer(trusted_roots=[self.issuer.public_key], clock_tolerance_secs=0)
        args = {**self.args, 'amount_cents': 40000}
        auth.check_chain([self.parent], 'pay_invoice', args,
                         self.parent.sign(self.agent, 'pay_invoice', args, int(time.time())))

    def test_changed_bank_with_real_holder_proof_denies(self):
        with self.assertRaises(Exception):
            self.verify({**self.args, 'bank_account': 'attacker-bank'})

    def test_changed_invoice_with_real_holder_proof_denies(self):
        with self.assertRaises(Exception):
            self.verify({**self.args, 'invoice_id': 'inv-124'})

    def test_missing_parent_fails_without_trusting_intermediate(self):
        with self.assertRaises(Exception):
            self.verify(self.args, chain=[self.child])

    def test_untrusted_root_fails(self):
        with self.assertRaises(Exception):
            self.verify(self.args, roots=[SigningKey.generate().public_key])

    def test_wrong_holder_signing_exact_challenge_fails(self):
        with self.assertRaises(Exception):
            self.verify(self.args, signer=SigningKey.generate())

    def test_terminal_child_cannot_delegate(self):
        with self.assertRaises(Exception):
            (self.child.grant_builder().capability('pay_invoice',
             invoice_id=Exact('inv-123'), bank_account=Exact('approved-bank'),
             amount_cents=Range(1, 25000)).holder(SigningKey.generate().public_key)
             .grant(self.worker))

    def test_released_high_level_mint_builder_has_no_depth_or_terminal_setter(self):
        self.assertFalse(hasattr(Warrant.mint_builder(), 'max_depth'))
        self.assertFalse(hasattr(Warrant.mint_builder(), 'terminal'))

    def test_allow_unknown_preserves_explicit_constraints(self):
        issuer, holder = SigningKey.generate(), SigningKey.generate()
        w = Warrant.mint(keypair=issuer, capabilities={'pay': {'amount': Range(1, 500), '_allow_unknown': True}},
                         holder=holder.public_key, ttl_seconds=60)
        a = Authorizer(trusted_roots=[issuer.public_key], clock_tolerance_secs=0)
        for args, allowed in [({'amount': 200, 'extra': 'admitted'}, True),
                              ({'amount': 501, 'extra': 'admitted'}, False),
                              ({'extra': 'admitted'}, False)]:
            proof = w.sign(holder, 'pay', args, int(time.time()))
            if allowed:
                a.check_chain([w], 'pay', args, proof)
            else:
                with self.assertRaises(Exception):
                    a.check_chain([w], 'pay', args, proof)

    def test_audit_parent_hash_is_raw_payload_hash(self):
        self.assertEqual(self.child.parent_hash, hashlib.sha256(self.parent.payload_bytes).hexdigest())

if __name__ == '__main__':
    print(json.dumps({'tenuo': importlib.metadata.version('tenuo'), 'skill_path': str(SKILL)}))
    unittest.main(verbosity=2)
