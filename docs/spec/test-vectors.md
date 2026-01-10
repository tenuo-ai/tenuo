# Tenuo Protocol Test Vectors

**Version:** 1.0  
**Generated:** 2024-01-01 (deterministic timestamps for reproducibility)  
**Specification:** [protocol-spec-v1.md](protocol-spec-v1.md)

---

## Overview

All test vectors are **byte-exact** and reproducible. Implementations MUST:

1. Reproduce the exact CBOR payload bytes
2. Verify signatures match exactly
3. Verify chain linkage via `parent_hash = SHA256(parent.payload)`

---

## Key Material

Keys are derived deterministically from 32-byte seeds using Ed25519.

| Role | Seed | Public Key |
|------|------|------------|
| Control Plane | `0101...01` (32×0x01) | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| Orchestrator | `0202...02` (32×0x02) | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Worker | `0303...03` (32×0x03) | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Worker2 | `0404...04` (32×0x04) | `ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c` |

**Full Seeds:**
```
Control Plane: 0101010101010101010101010101010101010101010101010101010101010101
Orchestrator:  0202020202020202020202020202020202020202020202020202020202020202
Worker:        0303030303030303030303030303030303030303030303030303030303030303
Worker2:       0404040404040404040404040404040404040404040404040404040404040404
```

---

## Timestamps

| Name | Unix (seconds) | ISO 8601 |
|------|----------------|----------|
| `issued_at` | `1704067200` | `2024-01-01T00:00:00Z` |
| `expires_at` | `1704070800` | `2024-01-01T01:00:00Z` |

---

## A.1 Minimal Valid Execution Warrant

Root warrant with `read_file` tool and Wildcard constraint.

**A.1**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000001` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (156 bytes):**
```
aa00010150019471f80000700080000000000000010269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
10f604820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25d
f60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf
1d94121bf3748801b40f6f5c061a65920080071a65920e9008031200
```

**Signature (64 bytes):**
```
eb112ef8cc34cace169bc0f52889e07096c0149980d1b2ed7e7b5c97a4143e8f599c47dbc21172320de707635c17d2d05447635d38a013698b8e02a5b7828200
```

**Complete SignedWarrant Envelope (228 bytes):**
```cbor
83                          # array(3)
   01                       # envelope_version = 1
   58 9c                    # payload (156 bytes)
      aa00010150019471f800007000800000...
   82                       # signature array(2)
      01                    # algorithm = Ed25519
      58 40                 # signature bytes (64)
         eb112ef8cc34cace169bc0f52889e070...
```

**Full Envelope CBOR (hex):**
```
8301589caa00010150019471f800007000800000000000000102696578656375
74696f6e03a169726561645f66696c65a16b636f6e73747261696e7473a16470
6174688210f604820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4
ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3cba5d72
ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008031200
82015840eb112ef8cc34cace169bc0f52889e07096c0149980d1b2ed7e7b5c97
a4143e8f599c47dbc21172320de707635c17d2d05447635d38a013698b8e02a5
b7828200
```

**Base64 (URL-safe, no padding):**
```
gwFYnKoAAQFQAZRx-AAAcACAAAAAAAAAAQJpZXhlY3V0aW9uA6FpcmVhZF9maWxloWtjb25zdHJh
aW50c6FkcGF0aIIQ9gSCAVgggTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5QFggFYIIqI
4910CfGV_VLbLTy6XXLKZwm_HZQSG_N0iAG0D29cBhplkgCABxplkg6QCAMSAIIBWEDrES74zDTK
zhabwPUoieBwlsAUmYDRsu1-e1yXpBQ-j1mcR9vCEXIyDecHY1wX0tBUR2NdOKATaYuOAqW3goIA
```

---

## A.2 Minimal Issuer Warrant

Issuer warrant that can grant `read_file` and `write_file` capabilities.

**A.2**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000002` |
| Type | Issuer |
| Depth | 0 |
| Max Depth | 5 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (146 bytes):**
```
ac00010150019471f8000070008000000000000002026669737375657203a004
820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b
8fc9b39405820158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d9412
1bf3748801b40f6f5c061a65920080071a65920e9008050b8269726561645f66
696c656a77726974655f66696c650d031200
```

**Signature (64 bytes):**
```
641e6ceab4abc76ff9bd5967d09808fe0a8efc65b7c918af11acfb118c94158747f8b02f0459dacb052ce5f1eda5d678e2dff2ced1b948d6123deeb48e25500f
```

---

## A.3 Valid 3-Level Chain

Demonstrates progressive attenuation:

```
Level 0: Pattern("/data/*")
    -> Level 1: Pattern("/data/reports/*")
          -> Level 2: Exact("/data/reports/q3.pdf")
```

### Level 0 (Root)

**Level 0**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000010` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (172 bytes):**
```
aa00010150019471f80000700080000000000000100269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e672f646174612f2a04820158208139770ea87d175f56
a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592
0080071a65920e9008031200
```

**Signature (64 bytes):**
```
941d60f6611abb8e079360160e06135fcf8de72d0fec056fdfc586b342f8a35c2affb7c727011da5707462a16b970ad60fdc34225accd9cc0bc44f271914e50d
```

### Level 1 (Attenuated)

**Invariants:**
- `issuer` = Level 0's `holder` (Orchestrator)
- `depth` = 1
- `parent_hash` = SHA256(Level 0 payload)

**Level 1**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000011` |
| Type | Execution |
| Depth | 1 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Parent Hash | `41ccd6219b0593c02563e525dc34fbd6e03682d760c9a87938d6aa8494d5c5fa` |

**Payload CBOR (246 bytes):**
```
ab00010150019471f80000700080000000000000110269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e6f2f646174612f7265706f7274732f2a0482015820ed
4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d105
820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b
8fc9b394061a65920080071a65920e900803099820184118cc18d61821189b05
189318c01825186318e5182518dc183418fb18d618e01836188218d7186018c9
18a81879183818d618aa1884189418d518c518fa1201
```

**Signature (64 bytes):**
```
e54c8ae27e4d852656e0d596556d2011953630663a4c93a9c7ee2407b89a2e71d82bec137f09e1b7e4e4768bf8f19d0df235e22762650e7bd588c3ead8d1790c
```

### Level 2 (Most Restricted)

**Invariants:**
- `issuer` = Level 1's `holder` (Worker)
- `depth` = 2
- `parent_hash` = SHA256(Level 1 payload)

**Level 2**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000012` |
| Type | Execution |
| Depth | 2 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c` |
| Issuer | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Parent Hash | `2bb296e57db02ce75712dfd41a7b9fa52d33357c086235b5ad8f75904f6c18f9` |

**Payload CBOR (248 bytes):**
```
ab00010150019471f80000700080000000000000120269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
01a16576616c7565742f646174612f7265706f7274732f71332e706466048201
5820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbda
be7c0582015820ed4928c628d1c2c6eae90338905995612959273a5c63f93636
c14614ac8737d1061a65920080071a65920e900803099820182b18b2189618e5
187d18b0182c18e718571218df18d4181a187b189f18a5182d18331835187c08
1862183518b518ad188f18751890184f186c181818f91202
```

**Signature (64 bytes):**
```
3df67259e4190b93095ad146a5b0b6d2c45e8d9115031628f75b76ce17dab1aa37a55509ebc16963ff7b508c492402e0e44f0a455900741efde312cb19ae850f
```

---

## A.4 Invalid Chain (I1 Violation)

**Scenario:** Attacker (Worker) signs attenuation of a warrant where they are NOT the holder.

Using Level 0 from A.3:

| Field | Level 0 | Invalid Child |
|-------|---------|---------------|
| holder | Orchestrator | Worker2 |
| issuer | Control Plane | **Worker** (WRONG) |

**Invalid Child Payload CBOR (238 bytes):**
```
ab00010150019471f80000700080000000000000400269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e672f646174612f2a0482015820ca93ac1705187071d6
7b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0582015820ed4928c6
28d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1061a6592
0080071a65920e900803099820184118cc18d61821189b05189318c018251863
18e5182518dc183418fb18d618e01836188218d7186018c918a81879183818d6
18aa1884189418d518c518fa1201
```

**Invalid Child Signature (64 bytes):**
```
8cd9457fec06791ab587aea5cf3b19437630e60d7adbe8cfb56bfce692ea2874bb9f3162645407a6b58316e2eb2d29ceb651b4f2582e083e45010a11e5774909
```

**Expected Error:** `child.issuer (ed4928c628d1c2c6) != parent.holder (8139770ea87d175f)`

Verifiers MUST reject this chain even though signatures are valid.

---

## A.5 Expired Warrant

Warrant with 1-second TTL.

**A.5**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000050` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704067201` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (156 bytes):**
```
aa00010150019471f80000700080000000000000500269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
10f604820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25d
f60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf
1d94121bf3748801b40f6f5c061a65920080071a6592008108031200
```

**Signature (64 bytes):**
```
c270f5d1468a09c84ca2de9040013c759eb10586b9373baf8486ad34be643be98a5b97f08fddc66f8add76e20989b1b8620c113ebcb793e27d793f1ae152ff0a
```

**Expected:** Reject with `warrant_expired` when `now > 1704067201`

---

## A.6 Proof-of-Possession

**A.6**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000060` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 1 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (179 bytes):**
```
aa00010150019471f80000700080000000000000600269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
01a16576616c7565702f646174612f7265706f72742e7064660482015820ed49
28c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10582
0158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4
0f6f5c061a65920080071a65920e9008011200
```

**Signature (64 bytes):**
```
af7ef8bd6527842e87d8db91c3614e93bc1ecabb58e99f87d11511bfcbce0605fa488b02388830720efe618f35470595e04176714cd4d15a294c9971789c2209
```

**PoP Challenge:**

| Component | Value |
|-----------|-------|
| Domain Separator | `b"tenuo-pop-v1"` |
| Warrant ID | `tnu_wrt_019471f8000070008000000000000060` |
| Tool | `read_file` |
| Args | `{"path": "/data/report.pdf"}` |
| Timestamp Window | `1704067200` |

**PoP Challenge CBOR (82 bytes):**
```
847828746e755f7772745f303139343731663830303030373030303830303030
303030303030303030363069726561645f66696c6581826470617468702f6461
74612f7265706f72742e7064661a65920080
```

**PoP Preimage (context || challenge):**
```
74656e756f2d706f702d7631  # "tenuo-pop-v1"
847828746e755f7772745f303139343731663830303030373030303830303030
303030303030303030363069726561645f66696c6581826470617468702f6461
74612f7265706f72742e7064661a65920080
```

**PoP Signature (64 bytes):**
```
84f11618ec5b7234287e3fc1dbb6f8c18de9aab1ad60d8bc3e26ba293814a0620cae3be2c96baf7698ef959105231d2b4eee57fa247a56c11170d100e66d6f0a
```

**Signing Key:** Worker private key (seed `0303...03`)

**Verification:** Signature MUST verify under Worker's public key: `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1`

---

## Implementation Notes

### CBOR Wire Format

Payload fields use integer keys:

| Key | Field |
|-----|-------|
| 0 | version |
| 1 | id |
| 2 | warrant_type |
| 3 | tools |
| 4 | holder |
| 5 | issuer |
| 6 | issued_at |
| 7 | expires_at |
| 8 | max_depth |
| 9 | parent_hash (optional) |
| 10 | extensions (optional) |
| 11 | issuable_tools (optional) |
| 12 | (reserved) |
| 13 | max_issue_depth (optional) |
| 14 | constraint_bounds (optional) |
| 15 | required_approvers (optional) |
| 16 | min_approvals (optional) |
| 17 | clearance (optional) |
| 18 | depth |

### Signature Message

The signature is computed over a domain-separated message:

```
message = b"tenuo-warrant-v1" || envelope_version || payload_cbor_bytes
signature = Ed25519.sign(issuer_key, message)
```

Where `envelope_version` is `0x01` for v1 warrants.

### Constraint Type IDs

| Type | ID |
|------|-----|
| Exact | 1 |
| Pattern | 2 |
| Wildcard | 16 |

---

## A.7 Edge Cases

### A.7.1 Terminal Warrant (depth = max_depth)

**Scenario:** Warrant at maximum delegation depth cannot be further attenuated.

| Field | Value |
|-------|-------|
| depth | 3 |
| max_depth | 3 |

**Expected:** Any attempt to attenuate this warrant MUST fail with `depth_exceeded`.

### A.7.2 Unknown Constraint Type

**Scenario:** Constraint with unrecognized type ID (experimental range).

**CBOR bytes:**
```
82          # array(2)
   18 80    # unsigned(128) - type ID in experimental range
   a1       # map(1)
      66    # text(6)
         637573746f6d  # "custom"
      64    # text(4)
         64617461      # "data"
```

**Hex:** `821880a166637573746f6d6464617461`

**Expected:** Verifier deserializes as `Constraint::Unknown { type_id: 128, payload: ... }`, authorization MUST fail (fail closed).

### A.7.3 Invalid CBOR: Duplicate Map Keys

**Scenario:** Malformed CBOR payload with duplicate keys.

```hex
# Map with duplicate key 0
a2 00 01 00 02
# {0: 1, 0: 2}
```

**Expected:** Senders MUST NOT produce. Verifier behavior is undefined per RFC 8949 §5.6. This is NOT a normative test case.

### A.7.4 SRL Revocation

**Scenario:** Warrant ID appears in Signed Revocation List.

| warrant.id | SRL.revoked_ids |
|------------|-----------------|
| `019471f8-0000-7000-8000-000000000001` | `[..., "019471f8-0000-7000-8000-000000000001", ...]` |

**Expected:** Authorization MUST fail with `warrant_revoked`.

---

## References

- **[RFC 8032]** Josefsson, S., Liusvaara, I., "Edwards-Curve Digital Signature Algorithm (EdDSA)", January 2017. https://datatracker.ietf.org/doc/html/rfc8032
- **[RFC 8949]** Bormann, C., Hoffman, P., "Concise Binary Object Representation (CBOR)", December 2020. https://datatracker.ietf.org/doc/html/rfc8949
- **[protocol-spec-v1.md]** Tenuo Protocol Specification
