import json
import unittest

from tenuo import Pattern, SigningKey, Warrant
from tenuo.exceptions import DeserializationError


class TestImplicitSerialization(unittest.TestCase):
    def test_str_and_constructor(self):
        # 1. Create a warrant
        key = SigningKey.generate()
        original_warrant = Warrant.mint(keypair=key, capabilities={"search": {"query": Pattern("*")}}, ttl_seconds=300)

        # 2. Test implicit serialization (str)
        token = str(original_warrant)
        self.assertTrue(len(token) > 0)  # Should be non-empty
        self.assertTrue(token.startswith("gw"))  # CBOR base64 prefix

        # 3. Test implicit deserialization (constructor)
        reconstituted_warrant = Warrant(token)

        # 4. Verify properties match
        self.assertEqual(original_warrant.id, reconstituted_warrant.id)
        self.assertEqual(original_warrant.tools, reconstituted_warrant.tools)

    def test_json_interop(self):
        # 1. Create warrant
        key = SigningKey.generate()
        warrant = Warrant.mint(keypair=key, capabilities={"search": {"query": Pattern("*")}}, ttl_seconds=60)

        # 2. Serialize in JSON structure
        data = {"warrant": str(warrant), "user": "alice"}
        json_str = json.dumps(data)

        # 3. Deserialize
        loaded = json.loads(json_str)
        warrant_from_json = Warrant(loaded["warrant"])

        self.assertEqual(warrant.id, warrant_from_json.id)

    def test_invalid_input(self):
        with self.assertRaises(DeserializationError):
            Warrant("not-base64-string")

    def test_legacy_methods(self):
        """Ensure old explicit methods still work."""
        key = SigningKey.generate()
        warrant = Warrant.mint(keypair=key, capabilities={"search": {"query": Pattern("*")}}, ttl_seconds=60)

        # 1. Explicit to_base64()
        token = warrant.to_base64()
        self.assertTrue(len(token) > 0)

        # 2. Explicit from_base64()
        reconstituted = Warrant.from_base64(token)
        self.assertEqual(warrant.id, reconstituted.id)

    def test_creation_methods_no_conflict(self):
        """Verify that constructor doesn't break static issue() methods."""
        key = SigningKey.generate()

        # 1. Static factory method (issue)
        w1 = Warrant.mint(keypair=key, capabilities={"a": {"p": Pattern("*")}}, ttl_seconds=60)
        self.assertIsInstance(w1, Warrant)

        # 2. Constructor (deserialization)
        token = str(w1)
        w2 = Warrant(token)
        self.assertIsInstance(w2, Warrant)

        # 3. They are distinct objects with same ID
        self.assertNotEqual(id(w1), id(w2))
        self.assertEqual(w1.id, w2.id)


if __name__ == "__main__":
    unittest.main()
