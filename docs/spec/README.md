# Tenuo Specification Documents

This directory contains the normative technical specifications for the Tenuo protocol.

## Documents

| Document | Description |
|----------|-------------|
| [protocol-spec-v1.md](protocol-spec-v1.md) | Protocol Specification - concepts, invariants, verification algorithms |
| [wire-format-v1.md](wire-format-v1.md) | Wire Format Specification - CBOR encoding, field IDs, serialization |
| [test-vectors.md](test-vectors.md) | Byte-exact test vectors for cross-implementation validation |

## For Implementers

1. Start with **protocol-spec-v1.md** to understand the security model and invariants
2. Use **wire-format-v1.md** for encoding/decoding details
3. Validate your implementation against **test-vectors.md**

## For Security Auditors

These documents are designed for formal review:
- All invariants are numbered (I1-I6) and referenced consistently
- Test vectors provide byte-exact validation targets
- Wire format uses CBOR per RFC 8949
