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
| Attacker | `ffff...ff` (32×0xFF) | `76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5` |

**Full Seeds:**
```
Control Plane: 0101010101010101010101010101010101010101010101010101010101010101
Orchestrator:  0202020202020202020202020202020202020202020202020202020202020202
Worker:        0303030303030303030303030303030303030303030303030303030303030303
Worker2:       0404040404040404040404040404040404040404040404040404040404040404
Attacker:      ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
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

## A.7 Extensions with CBOR Values

**Scenario:** Warrant with CBOR-encoded extension values.

Extensions demonstrate:

1. Simple string values (CBOR-encoded)
2. Structured data (CBOR-encoded)
3. Preservation through serialization/deserialization

**A.7**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000070` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (364 bytes):**
```
ab00010150019471f80000700080000000000000700269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
01a16576616c7565702f646174612f7265706f72742e70646604820158208139
770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940582
0158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4
0f6f5c061a65920080071a65920e9008030aa273636f6d2e6578616d706c652e
62696c6c696e67983818a31864187418651861186d186b186d186c182d187218
65187318651861187218631868186718701872186f186a186518631874186e18
771861187218721861186e1874182d18731879187318741865186d186b186318
6f18731874185f18631865186e187418651872181910186974636f6d2e657861
6d706c652e74726163655f69648e186d1872186518711875186518731874182d
183118321833183418351200
```

**Signature (64 bytes):**
```
20ee2c6299dca2ade227cdee2272c09c696fd888547c7b9f03b2d5c0d4e15743086212bf85612ba5d84012276ea55ec3696598991bc93bd3a2ef496099a82506
```

**Extension Values (CBOR-encoded):**

| Key | Type | CBOR Encoding |
|-----|------|---------------|
| `com.example.trace_id` | String | `6d726571756573742d3132333435` |
| `com.example.billing` | Struct | `a3647465616d6b6d6c2d72657365617263686770726f6a6563746e77617272616e742d73797374656d6b636f73745f63656e746572191069` |

**Decoded Extension Values:**

```rust
// com.example.trace_id
let trace_id: String = cbor::decode(extensions["com.example.trace_id"])?;
assert_eq!(trace_id, "request-12345");

// com.example.billing
struct BillingTag {
    team: String,
    project: String,
    cost_center: u32,
}
let billing: BillingTag = cbor::decode(extensions["com.example.billing"])?;
assert_eq!(billing.team, "ml-research");
assert_eq!(billing.project, "warrant-system");
assert_eq!(billing.cost_center, 4201);
```

**Verification:**

1. Extensions are included in the warrant signature
2. Extension values MUST be CBOR-encoded (not raw bytes)
3. Extensions survive serialization/deserialization round-trip
4. Unknown extension keys are preserved (not stripped)

---

## A.8 WarrantStack Serialization

**Scenario:** Transporting a 3-level delegation chain as a single CBOR array.

A `WarrantStack` is a CBOR array of warrants ordered Root → Leaf:

```
type WarrantStack = Vec<SignedWarrant>;
```

**WarrantStack CBOR (883 bytes):**
```
83830158acaa00010150019471f8000070008000000000000010026965786563
7574696f6e03a169726561645f66696c65a16b636f6e73747261696e7473a164
706174688202a1677061747465726e672f646174612f2a04820158208139770e
a87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158
208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f
5c061a65920080071a65920e900803120082015840941d60f6611abb8e079360
160e06135fcf8de72d0fec056fdfc586b342f8a35c2affb7c727011da5707462
a16b970ad60fdc34225accd9cc0bc44f271914e50d830158f6ab000101500194
71f80000700080000000000000110269657865637574696f6e03a16972656164
5f66696c65a16b636f6e73747261696e7473a164706174688202a16770617474
65726e6f2f646174612f7265706f7274732f2a0482015820ed4928c628d1c2c6
eae90338905995612959273a5c63f93636c14614ac8737d10582015820813977
0ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394061a65
920080071a65920e900803099820184118cc18d61821189b05189318c0182518
6318e5182518dc183418fb18d618e01836188218d7186018c918a81879183818
d618aa1884189418d518c518fa120182015840e54c8ae27e4d852656e0d59655
6d2011953630663a4c93a9c7ee2407b89a2e71d82bec137f09e1b7e4e4768bf8
f19d0df235e22762650e7bd588c3ead8d1790c830158f8ab00010150019471f8
0000700080000000000000120269657865637574696f6e03a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688201a16576616c756574
2f646174612f7265706f7274732f71332e7064660482015820ca93ac17051870
71d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0582015820ed49
28c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1061a
65920080071a65920e900803099820182b18b2189618e5187d18b0182c18e718
571218df18d4181a187b189f18a5182d18331835187c081862183518b518ad18
8f18751890184f186c181818f91202820158403df67259e4190b93095ad146a5
b0b6d2c45e8d9115031628f75b76ce17dab1aa37a55509ebc16963ff7b508c49
2402e0e44f0a455900741efde312cb19ae850f
```

**WarrantStack Structure:**
```cbor
83                  # array(3)
   # warrant_l0 (envelope)
   83               # array(3) - SignedWarrant
      01            # envelope_version
      58 AC         # payload (172 bytes)
      82 01 58 40   # signature
   # warrant_l1 (envelope)
   83               # array(3) - SignedWarrant
      01            # envelope_version
      58 F6         # payload (246 bytes)
      82 01 58 40   # signature
   # warrant_l2 (envelope)
   83               # array(3) - SignedWarrant
      01            # envelope_version
      58 F8         # payload (248 bytes)
      82 01 58 40   # signature
```

**Base64 (URL-safe, no padding):**
```
g4MBWKyqAAEBUAGUcfgAAHAAgAAAAAAAABACaWV4ZWN1dGlvbgOhaXJlYWRfZmlsZaFrY29uc3Ry
YWludHOhZHBhdGiCAqFncGF0dGVybmcvZGF0YS8qBIIBWCCBOXcOqH0XX1ajVGbDTH7My42KkbTu
N6Jd9g9bj8mzlAWCAVggiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1wGGmWSAIAHGmWS
DpAIAxIAggFYQJQdYPZhGruOB5NgFg4GE1_PjectD-wFb9_FhrNC-KNcKv-3xycBHaVwdGKha5cK
1g_cNCJazNnMC8RPJxkU5Q2DAVj2qwABAVABlHH4AABwAIAAAAAAAAARAmlleGVjdXRpb24DoWly
ZWFkX2ZpbGWha2NvbnN0cmFpbnRzoWRwYXRoggKhZ3BhdHRlcm5vL2RhdGEvcmVwb3J0cy8qBIIB
WCDtSSjGKNHCxurpAziQWZVhKVknOlxj-TY2wUYUrIc30QWCAVgggTl3Dqh9F19Wo1Rmw0x-zMuN
ipG07jeiXfYPW4_Js5QGGmWSAIAHGmWSDpAIAwmYIBhBGMwY1hghGJsFGJMYwBglGGMY5RglGNwY
NBj7GNYY4Bg2GIIY1xhgGMkYqBh5GDgY1hiqGIQYlBjVGMUY-hIBggFYQOVMiuJ-TYUmVuDVllVt
IBGVNjBmOkyTqcfuJAe4mi5x2CvsE38J4bfk5HaL-PGdDfI14idiZQ571YjD6tjReQyDAVj4qwAB
AVABlHH4AABwAIAAAAAAAAASAmlleGVjdXRpb24DoWlyZWFkX2ZpbGWha2NvbnN0cmFpbnRzoWRw
YXRoggGhZXZhbHVldC9kYXRhL3JlcG9ydHMvcTMucGRmBIIBWCDKk6wXBRhwcdZ7g8f_Dv6BCOjs
RTBXXXcmh5Mz29q-fAWCAVgg7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9EGGmWSAIAH
GmWSDpAIAwmYIBgrGLIYlhjlGH0YsBgsGOcYVxIY3xjUGBoYexifGKUYLRgzGDUYfAgYYhg1GLUY
rRiPGHUYkBhPGGwYGBj5EgKCAVhAPfZyWeQZC5MJWtFGpbC20sRejZEVAxYo91t2zhfasao3pVUJ
68FpY_97UIxJJALg5E8KRVkAdB794xLLGa6FDw
```

**Verification steps:**

1. Deserialize as `Vec<SignedWarrant>` (3 elements)
2. Verify warrant_l0 signature (control plane key)
3. Verify warrant_l1:
   - Issuer = warrant_l0.holder
   - parent_hash = SHA256(warrant_l0.payload)
   - depth = 1, expires_at ≤ warrant_l0.expires_at
   - Signature valid (orchestrator key)
4. Verify warrant_l2:
   - Issuer = warrant_l1.holder
   - parent_hash = SHA256(warrant_l1.payload)
   - depth = 2, expires_at ≤ warrant_l1.expires_at
   - Signature valid (worker key)

---

## A.9 Edge Cases

### A.9.1 Terminal Warrant (depth = max_depth)

**Scenario:** Warrant at maximum delegation depth cannot be further attenuated.

| Field | Value |
|-------|-------|
| depth | 3 |
| max_depth | 3 |

**Expected:** Any attempt to attenuate this warrant MUST fail with `depth_exceeded`.

### A.9.2 Unknown Constraint Type

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

### A.9.3 Invalid CBOR: Duplicate Map Keys

**Scenario:** Malformed CBOR payload with duplicate keys.

```hex
# Map with duplicate key 0
a2 00 01 00 02
# {0: 1, 0: 2}
```

**Expected:** Senders MUST NOT produce. Verifier behavior is undefined per RFC 8949 §5.6. This is NOT a normative test case.

### A.9.4 SRL Revocation

**Scenario:** Warrant ID appears in Signed Revocation List.

| warrant.id | SRL.revoked_ids |
|------------|-----------------|
| `019471f8-0000-7000-8000-000000000001` | `[..., "019471f8-0000-7000-8000-000000000001", ...]` |

**Expected:** Authorization MUST fail with `warrant_revoked`.

---

## A.10 Invalid Depth Monotonicity (I2 Violation)

**Scenario:** Child warrant skips a depth level (child.depth != parent.depth + 1).

**A.10 Parent**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000090` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (172 bytes):**
```
aa00010150019471f80000700080000000000000900269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e672f646174612f2a04820158208139770ea87d175f56
a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592
0080071a65920e9008031200
```

**Signature (64 bytes):**
```
38a97e6c250295cf8e8bd611f23b2a5af30d466906d7a90b03de9e1f66cb24334db580341db62296711f3e4ffc62349f3c2cd1a436e371bb0c3d4dc45e5aaf09
```

**A.10 Child (Invalid)**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000091` |
| Type | Execution |
| Depth | 2 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Parent Hash | `b39a4af4367ea5b8d69adfc3677e8f28f1965da03003a8e30a15f39fe687fcdb` |

**Payload CBOR (244 bytes):**
```
ab00010150019471f80000700080000000000000910269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e6f2f646174612f7265706f7274732f2a0482015820ed
4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d105
820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b
8fc9b394061a65920080071a65920e90080309982018b3189a184a18f4183618
7e18a518b818d6189a18df18c31867187e188f182818f11896185d18a0183003
18a818e30a1518f3189f18e6188718fc18db1202
```

**Signature (64 bytes):**
```
3b869a8c0833d4d6348869290b829203defe4dc6d8748592fd693718209a08150fa3bb9ee4e2d714fc9c1ef1bfa17c5a4b74d7aa0c5ecccc75b888673a8fe00b
```

**Depth Comparison:**

| Warrant | Depth | Expected |
|---------|-------|----------|
| Parent  | 0     | -        |
| Child   | 2     | 1        |

**Expected:** Verification MUST fail with `depth_monotonicity_violated`.

**Invariant I2:** `child.depth == parent.depth + 1`

---

## A.11 Invalid Capability Monotonicity (I4 Violation)

**Scenario:** Child warrant attempts to expand authority beyond parent's grants.

**A.11 Parent**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000092` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (180 bytes):**
```
aa00010150019471f80000700080000000000000920269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e6f2f646174612f7265706f7274732f2a048201582081
39770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405
820158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801
b40f6f5c061a65920080071a65920e9008031200
```

**Signature (64 bytes):**
```
f6348e3f64495188d91edde954e86623caea13388d4f7faa9f4968f0f532b4dff5b1c0125dc28df02813f86a065e0eea6901d130e8dec5803eb58ea79261be0a
```

**A.11 Child (Invalid)**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000093` |
| Type | Execution |
| Depth | 1 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Parent Hash | `684cdad50159a191ef8f024dc82a150410aef382cc5fd07401fc9b97d30facf3` |

**Payload CBOR (232 bytes):**
```
ab00010150019471f80000700080000000000000930269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e672f646174612f2a0482015820ed4928c628d1c2c6ea
e90338905995612959273a5c63f93636c14614ac8737d105820158208139770e
a87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394061a6592
0080071a65920e9008030998201868184c18da18d501185918a1189118ef188f
02184d18c8182a15041018ae18f3188218cc185f18d018740118fc189b189718
d30f18ac18f31201
```

**Signature (64 bytes):**
```
211c5c8a8b1c1f911b8e0499130384cc529a1bbd3b949ef9753398ea5fa1ffae2b917e48e17556b43d13c4d1adaa0873ff605ee15c3f034ca24db4ee9ff66f0e
```

**Constraint Comparison:**

| Warrant | path Constraint | Matches |
|---------|-----------------|---------|
| Parent  | `/data/reports/*` | `/data/reports/foo`, `/data/reports/bar` |
| Child   | `/data/*` | `/data/foo`, `/data/reports/foo`, `/data/secret/key` |

**Expected:** Verification MUST fail with `capability_monotonicity_violated`.

**Invariant I4:** Child constraints must be equal or more restrictive than parent.
---

## A.12 Invalid Parent Hash (I5 Violation)

**Scenario:** Child warrant claims to delegate from parent but parent_hash doesn't match SHA256(parent.payload).

**A.12 Parent**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f80000700080000000000000a0` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (172 bytes):**
```
aa00010150019471f80000700080000000000000a00269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e672f646174612f2a04820158208139770ea87d175f56
a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592
0080071a65920e9008031200
```

**Signature (64 bytes):**
```
4e3bc36f5f718cda1f26f1e711d40b208c801dde6d8d5f33426241075f8dd1a21c3e28f24f2787b364f6f983e54cb9e7c60e403cb89e485f2b0e336c53d05603
```

**A.12 Child (Invalid)**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f80000700080000000000000a1` |
| Type | Execution |
| Depth | 1 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Parent Hash | `0000000000000000000000000000000000000000000000000000000000000000` |

**Payload CBOR (215 bytes):**
```
ab00010150019471f80000700080000000000000a10269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e6f2f646174612f7265706f7274732f2a0482015820ed
4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d105
820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b
8fc9b394061a65920080071a65920e9008030998200000000000000000000000
0000000000000000000000000000000000000000001201
```

**Signature (64 bytes):**
```
9b87f984431fdb021aa5331b0960dd2a535df812c0d7c916168b495a9fdbb38e43a5a9a0ac2a1e65dc0076338deaa5da962f915588532ef1c8cd8916193ab806
```

**Parent Hash Comparison:**

| Field | Value |
|-------|-------|
| Correct parent_hash | `e7d3e3e8cab3f920e623453f4c718ef5f440edde9ecd0140ecfff7502e073e45` |
| Child's parent_hash | `0000000000000000000000000000000000000000000000000000000000000000` |

**Expected:** Verification MUST fail with `parent_hash_mismatch`.

**Invariant I5:** `child.parent_hash == SHA256(parent.payload_bytes)`

---

## A.13 TTL Extension Attack (I3 Violation)

**Scenario:** Child warrant attempts to extend lifetime beyond parent's expiration.

**A.13 Parent**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f80000700080000000000000b0` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (172 bytes):**
```
aa00010150019471f80000700080000000000000b00269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e672f646174612f2a04820158208139770ea87d175f56
a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592
0080071a65920e9008031200
```

**Signature (64 bytes):**
```
dc3d49adf4868a697512776fcb7bbe2b3ff35f7ae0d27b9546f4a98796d706e4f354b5e3bc1cee877d6404f20996e0e130d40358ea7468338144d5bdecb6950e
```

**A.13 Child (Invalid)**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f80000700080000000000000b1` |
| Type | Execution |
| Depth | 1 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704074400` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Parent Hash | `42d853f77531dcb141f05c3f43b2c28285f251675e21e053c8ab82dbfc60cbf5` |

**Payload CBOR (247 bytes):**
```
ab00010150019471f80000700080000000000000b10269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e6f2f646174612f7265706f7274732f2a0482015820ed
4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d105
820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b
8fc9b394061a65920080071a65921ca00803099820184218d8185318f7187518
3118dc18b1184118f0185c183f184318b218c21882188518f218511867185e18
2118e0185318c818ab188218db18fc186018cb18f51201
```

**Signature (64 bytes):**
```
cdb83eb10d561edb54de001096bc80df3cb5ef9dd0f67134e1c4eeb52bc6d94e4f3b6284686fa319539f3218188c5b1634ae9757c02999d2baab5d2d5c54e604
```

**TTL Comparison:**

| Field | Parent | Child | Valid? |
|-------|--------|-------|--------|
| issued_at | 1704067200 | 1704067200 | YES |
| expires_at | 1704070800 | 1704074400 | NO (child > parent) |

**Expected:** Verification MUST fail with `ttl_monotonicity_violated`.

**Invariant I3:** `child.expires_at <= parent.expires_at`

---

## A.14 Invalid Signature (Cryptographic Verification)

**Scenario:** Warrant payload is valid but signature was created by wrong key.

This tests that implementations correctly verify Ed25519 signatures. A common
implementation bug is to skip signature verification or verify against the wrong key.

**A.14 Forged (Invalid Signature)**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f80000700080000000000000c0` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (172 bytes):**
```
aa00010150019471f80000700080000000000000c00269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e672f646174612f2a04820158208139770ea87d175f56
a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592
0080071a65920e9008031200
```

**Signature (64 bytes):**
```
fc2d4c07b9f0b6c1955e0f3782cd505300d684dd3bd0de70252ca7099b6ef8016f2c9a349a1a7d30c2bd63a15a9e3555d5b50c76d6721d3e86ac8dc32f7e7508
```

**A.14 Valid (Correct Signature)**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f80000700080000000000000c0` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (172 bytes):**
```
aa00010150019471f80000700080000000000000c00269657865637574696f6e
03a169726561645f66696c65a16b636f6e73747261696e7473a1647061746882
02a1677061747465726e672f646174612f2a04820158208139770ea87d175f56
a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592
0080071a65920e9008031200
```

**Signature (64 bytes):**
```
5c0063e566238e19c27394e0093e09b40ab750c8878a2edb83b051f01ff6469ac3447b19f02d4e8f230a024c9d0dbb236b53a2bb5d439cdff7929627bc5b690d
```

**Key Comparison:**

| Field | Value |
|-------|-------|
| Claimed issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| Actual signer (forged) | `76a1592044a6e4f511265bca73a604d90b0529d1df602be30a19a9257660d1f5` |
| Actual signer (valid) | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Note:** The payload bytes are IDENTICAL between forged and valid warrants.
Only the signature differs.

**Expected:** Verification MUST fail with `signature_invalid` or `signature_verification_failed`.

**Security Note:** This is a critical security check. Implementations that skip
signature verification would accept forged warrants, completely breaking the
security model.

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

## References

- **[RFC 8032]** Josefsson, S., Liusvaara, I., "Edwards-Curve Digital Signature Algorithm (EdDSA)", January 2017. https://datatracker.ietf.org/doc/html/rfc8032
- **[RFC 8949]** Bormann, C., Hoffman, P., "Concise Binary Object Representation (CBOR)", December 2020. https://datatracker.ietf.org/doc/html/rfc8949
- **[protocol-spec-v1.md]** Tenuo Protocol Specification
