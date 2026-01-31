   Compiling tenuo v0.1.0-beta.7 (/Users/aimable/Development/tenuo/tenuo-core)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.26s
     Running `target/debug/generate_test_vectors`
# Tenuo Protocol Test Vectors

**Version:** 1.0
**Documentation Revision:** 2 (2026-01-21)
**Generated:** 2024-01-01 (deterministic timestamps for reproducibility)
**Specification:** [wire-format-v1.md](wire-format-v1.md)

---

## Revision History

- **Rev 2** (2026-01-21): Documentation cleanup
  - Regenerated all test vectors to match current generator output
  - Added cross-reference note to full constraint type list in wire-format-v1.md
  - **No protocol changes** - test vectors remain v1.0 compatible

- **Rev 1** (2026-01-01): Initial release

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

**Payload CBOR (147 bytes):**
```
aa00010150019471f8000070008000000000000001020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688210f604820158208139
770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940582
0158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4
0f6f5c061a65920080071a65920e9008031200
```

**Signature (64 bytes):**
```
4396783e89f37eebfa7d25ad7d61d6cddfbb6c58eade0e9ccc6e28759f1eb56b3c03873a6232483d05f766481edf9f85560881aed03b6ef25771285409e6d800
```

**Complete SignedWarrant Envelope (219 bytes):**
```cbor
83                          # array(3)
   01                       # envelope_version = 1
   58 93                    # payload (147 bytes)
      aa00010150019471f800007000800000...
   82                       # signature array(2)
      01                    # algorithm = Ed25519
      58 40                 # signature bytes (64)
         4396783e89f37eebfa7d25ad7d61d6cd...
```

**Full Envelope CBOR (hex):**
```
83015893aa00010150019471f8000070008000000000000001020003a1697265
61645f66696c65a16b636f6e73747261696e7473a164706174688210f6048201
58208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9
b39405820158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3
748801b40f6f5c061a65920080071a65920e9008031200820158404396783e89
f37eebfa7d25ad7d61d6cddfbb6c58eade0e9ccc6e28759f1eb56b3c03873a62
32483d05f766481edf9f85560881aed03b6ef25771285409e6d800
```

**Base64 (URL-safe, no padding):**
```
gwFYk6oAAQFQAZRx-AAAcACAAAAAAAAAAQIAA6FpcmVhZF9maWxloWtjb25zdHJhaW50c6FkcGF0
aIIQ9gSCAVgggTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5QFggFYIIqI4910CfGV_VLb
LTy6XXLKZwm_HZQSG_N0iAG0D29cBhplkgCABxplkg6QCAMSAIIBWEBDlng-ifN-6_p9Ja19YdbN
37tsWOreDpzMbih1nx61azwDhzpiMkg9BfdmSB7fn4VWCIGu0Dtu8ldxKFQJ5tgA
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

**Payload CBOR (140 bytes):**
```
ac00010150019471f8000070008000000000000002020103a004820158208139
770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940582
0158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4
0f6f5c061a65920080071a65920e9008050b8269726561645f66696c656a7772
6974655f66696c650d031200
```

**Signature (64 bytes):**
```
a00345650d5ede861ee944a42012b8c7b9f8f7172a5f750e7c9bec592118b15effd554ec7c2d020c10bd38c37369104ae79d91e3acf8bd22b344ba8b1291d707
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

**Payload CBOR (163 bytes):**
```
aa00010150019471f8000070008000000000000010020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a04820158208139770ea87d175f56a35466c34c7ecccb8d
8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
031200
```

**Signature (64 bytes):**
```
98bcd71626112aded9d4d1aa728580934d908611ea15fb90a44b4efb00ad51145dbe1c5ee1b2ba5790bc1215bd9805b2b06449b271f5a8fd080564cba2335a09
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
| Parent Hash | `705e79416823ef819a08e0c59feccb5d4baed4a7ebcaca290b014112cec5fc64` |

**Payload CBOR (234 bytes):**
```
ab00010150019471f8000070008000000000000011020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e6f2f646174612f7265706f7274732f2a0482015820ed4928c628d1c2c6eae9
0338905995612959273a5c63f93636c14614ac8737d105820158208139770ea8
7d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394061a659200
80071a65920e9008030998201870185e187918411868182318ef1881189a0818
e018c5189f18ec18cb185d184b18ae18d418a718eb18ca18ca18290b01184112
18ce18c518fc18641201
```

**Signature (64 bytes):**
```
a3ec5b753afad510ffa1145ce686f930470976dd93b5da08a6bf26fdaaac60d7c3420d5c87021fe63713e06f1a2a60360dea7f3776a0f28da0bb3d42c3319906
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
| Parent Hash | `4a94bb94771e4ed44cc40acb7f8b0164cdb008af948cb195900637ff6e98f99b` |

**Payload CBOR (237 bytes):**
```
ab00010150019471f8000070008000000000000012020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688201a16576616c756574
2f646174612f7265706f7274732f71332e7064660482015820ca93ac17051870
71d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0582015820ed49
28c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1061a
65920080071a65920e900803099820184a189418bb18941877181e184e18d418
4c18c40a18cb187f188b01186418cd18b00818af1894188c18b1189518900618
3718ff186e189818f9189b1202
```

**Signature (64 bytes):**
```
f47307c756b98144fd4eeac30c157e317a307da7630db619001f531c479128fd1997c666baf0d020e8d60619bb8644f79a5a0038836d49b2a1f676fc7ee8d307
```

---

## A.4 Invalid Chain (I1 Violation)

**Scenario:** Attacker (Worker) signs attenuation of a warrant where they are NOT the holder.

Using Level 0 from A.3:

| Field | Level 0 | Invalid Child |
|-------|---------|---------------|
| holder | Orchestrator | Worker2 |
| issuer | Control Plane | **Worker** (WRONG) |

**Invalid Child Payload CBOR (226 bytes):**
```
ab00010150019471f8000070008000000000000040020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a0482015820ca93ac1705187071d67b83c7ff0efe8108e8
ec4530575d7726879333dbdabe7c0582015820ed4928c628d1c2c6eae9033890
5995612959273a5c63f93636c14614ac8737d1061a65920080071a65920e9008
030998201870185e187918411868182318ef1881189a0818e018c5189f18ec18
cb185d184b18ae18d418a718eb18ca18ca18290b0118411218ce18c518fc1864
1201
```

**Invalid Child Signature (64 bytes):**
```
93d9c6d8a26fb450f9245c9cfec0a34dc8033bb08ed669d6f19502d1da0d35d564b1a3767a2a469353417136ebc6ed9b27645b806c708baadc3dde27b4116f0c
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

**Payload CBOR (147 bytes):**
```
aa00010150019471f8000070008000000000000050020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688210f604820158208139
770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940582
0158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4
0f6f5c061a65920080071a6592008108031200
```

**Signature (64 bytes):**
```
13c824cd5c27c5fc1b6c0fd36ed0579d3278a1dd8df2b5e941679e25890f3129530dfd1ba49d4691bbb56aa30f4eafdeea15e60a4f20c61c56bcf888404f4f0a
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

**Payload CBOR (170 bytes):**
```
aa00010150019471f8000070008000000000000060020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688201a16576616c756570
2f646174612f7265706f72742e7064660482015820ed4928c628d1c2c6eae903
38905995612959273a5c63f93636c14614ac8737d105820158208a88e3dd7409
f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080
071a65920e9008011200
```

**Signature (64 bytes):**
```
3c170967a561d9bf81c4d45398fa6defdddfcb87157bde9e597a7e16abca5c226b31199e57ca87953ce814a178c6e018835c8a24c50afbc4bcdc8d485a9d5a0c
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

**Payload CBOR (355 bytes):**
```
ab00010150019471f8000070008000000000000070020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688201a16576616c756570
2f646174612f7265706f72742e70646604820158208139770ea87d175f56a354
66c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd7409
f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080
071a65920e9008030aa273636f6d2e6578616d706c652e62696c6c696e679838
18a31864187418651861186d186b186d186c182d187218651873186518611872
18631868186718701872186f186a186518631874186e18771861187218721861
186e1874182d18731879187318741865186d186b1863186f18731874185f1863
1865186e187418651872181910186974636f6d2e6578616d706c652e74726163
655f69648e186d1872186518711875186518731874182d183118321833183418
351200
```

**Signature (64 bytes):**
```
e760545471300ee3493c16336d8013b3e815c34fb79179a490570a016d8a034730f22302bded9573b8264d0700e85cd93fbf683ef4648973fa11ae63a50b5900
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

**WarrantStack CBOR (851 bytes):**
```
83830158a3aa00010150019471f8000070008000000000000010020003a16972
6561645f66696c65a16b636f6e73747261696e7473a164706174688202a16770
61747465726e672f646174612f2a04820158208139770ea87d175f56a35466c3
4c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195
fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a
65920e90080312008201584098bcd71626112aded9d4d1aa728580934d908611
ea15fb90a44b4efb00ad51145dbe1c5ee1b2ba5790bc1215bd9805b2b06449b2
71f5a8fd080564cba2335a09830158eaab00010150019471f800007000800000
0000000011020003a169726561645f66696c65a16b636f6e73747261696e7473
a164706174688202a1677061747465726e6f2f646174612f7265706f7274732f
2a0482015820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c1
4614ac8737d105820158208139770ea87d175f56a35466c34c7ecccb8d8a91b4
ee37a25df60f5b8fc9b394061a65920080071a65920e9008030998201870185e
187918411868182318ef1881189a0818e018c5189f18ec18cb185d184b18ae18
d418a718eb18ca18ca18290b0118411218ce18c518fc1864120182015840a3ec
5b753afad510ffa1145ce686f930470976dd93b5da08a6bf26fdaaac60d7c342
0d5c87021fe63713e06f1a2a60360dea7f3776a0f28da0bb3d42c33199068301
58edab00010150019471f8000070008000000000000012020003a16972656164
5f66696c65a16b636f6e73747261696e7473a164706174688201a16576616c75
65742f646174612f7265706f7274732f71332e7064660482015820ca93ac1705
187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c0582015820
ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1
061a65920080071a65920e900803099820184a189418bb18941877181e184e18
d4184c18c40a18cb187f188b01186418cd18b00818af1894188c18b118951890
06183718ff186e189818f9189b120282015840f47307c756b98144fd4eeac30c
157e317a307da7630db619001f531c479128fd1997c666baf0d020e8d60619bb
8644f79a5a0038836d49b2a1f676fc7ee8d307
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
g4MBWKOqAAEBUAGUcfgAAHAAgAAAAAAAABACAAOhaXJlYWRfZmlsZaFrY29uc3RyYWludHOhZHBh
dGiCAqFncGF0dGVybmcvZGF0YS8qBIIBWCCBOXcOqH0XX1ajVGbDTH7My42KkbTuN6Jd9g9bj8mz
lAWCAVggiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1wGGmWSAIAHGmWSDpAIAxIAggFY
QJi81xYmESre2dTRqnKFgJNNkIYR6hX7kKRLTvsArVEUXb4cXuGyuleQvBIVvZgFsrBkSbJx9aj9
CAVky6IzWgmDAVjqqwABAVABlHH4AABwAIAAAAAAAAARAgADoWlyZWFkX2ZpbGWha2NvbnN0cmFp
bnRzoWRwYXRoggKhZ3BhdHRlcm5vL2RhdGEvcmVwb3J0cy8qBIIBWCDtSSjGKNHCxurpAziQWZVh
KVknOlxj-TY2wUYUrIc30QWCAVgggTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5QGGmWS
AIAHGmWSDpAIAwmYIBhwGF4YeRhBGGgYIxjvGIEYmggY4BjFGJ8Y7BjLGF0YSxiuGNQYpxjrGMoY
yhgpCwEYQRIYzhjFGPwYZBIBggFYQKPsW3U6-tUQ_6EUXOaG-TBHCXbdk7XaCKa_Jv2qrGDXw0IN
XIcCH-Y3E-BvGipgNg3qfzd2oPKNoLs9QsMxmQaDAVjtqwABAVABlHH4AABwAIAAAAAAAAASAgAD
oWlyZWFkX2ZpbGWha2NvbnN0cmFpbnRzoWRwYXRoggGhZXZhbHVldC9kYXRhL3JlcG9ydHMvcTMu
cGRmBIIBWCDKk6wXBRhwcdZ7g8f_Dv6BCOjsRTBXXXcmh5Mz29q-fAWCAVgg7UkoxijRwsbq6QM4
kFmVYSlZJzpcY_k2NsFGFKyHN9EGGmWSAIAHGmWSDpAIAwmYIBhKGJQYuxiUGHcYHhhOGNQYTBjE
ChjLGH8YiwEYZBjNGLAIGK8YlBiMGLEYlRiQBhg3GP8YbhiYGPkYmxICggFYQPRzB8dWuYFE_U7q
wwwVfjF6MH2nYw22GQAfUxxHkSj9GZfGZrrw0CDo1gYZu4ZE95paADiDbUmyofZ2_H7o0wc
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

**Payload CBOR (163 bytes):**
```
aa00010150019471f8000070008000000000000090020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a04820158208139770ea87d175f56a35466c34c7ecccb8d
8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
031200
```

**Signature (64 bytes):**
```
1aeca9111a8c5ab0960068c99942f52fea76f3971c43103d9d26ffb238469a970872502b745d0004a225306b03cd19ceb98100b4e4d15a5d005d1286837a950e
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
| Parent Hash | `a3a5fad2aa1a6dffe577b792308984988993178cd3915a1f004a6b9f451e7f76` |

**Payload CBOR (236 bytes):**
```
ab00010150019471f8000070008000000000000091020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e6f2f646174612f7265706f7274732f2a0482015820ed4928c628d1c2c6eae9
0338905995612959273a5c63f93636c14614ac8737d105820158208139770ea8
7d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394061a659200
80071a65920e90080309982018a318a518fa18d218aa181a186d18ff18e51877
18b7189218301889188418981889189317188c18d31891185a181f00184a186b
189f1845181e187f18761202
```

**Signature (64 bytes):**
```
06a7a33609ffdd035eafba2e005180bfdf07ba136da4f421687bfa372f0a2c0c2dc47a5b830c594491eca9370c36a9caeb1ee8f6536463c830ab9a8977df6004
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

**Payload CBOR (171 bytes):**
```
aa00010150019471f8000070008000000000000092020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e6f2f646174612f7265706f7274732f2a04820158208139770ea87d175f56a3
5466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd74
09f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a659200
80071a65920e9008031200
```

**Signature (64 bytes):**
```
598ad233d691c13f2f0526b4739920534f209b62b018eacac1caff4a925a167393de0a2d9517f81454b150288705de0d5b8d02090d9e23a77ed9225cef96fb0a
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
| Parent Hash | `67ef0bacd1ff9e65c68517a85f7aef3b94af3f7b19eae74f3ac6fffbeb95b161` |

**Payload CBOR (228 bytes):**
```
ab00010150019471f8000070008000000000000093020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a0482015820ed4928c628d1c2c6eae90338905995612959
273a5c63f93636c14614ac8737d105820158208139770ea87d175f56a35466c3
4c7ecccb8d8a91b4ee37a25df60f5b8fc9b394061a65920080071a65920e9008
03099820186718ef0b18ac18d118ff189e186518c618851718a8185f187a18ef
183b189418af183f187b181918ea18e7184f183a18c618ff18fb18eb189518b1
18611201
```

**Signature (64 bytes):**
```
5376bb550974af9583787578e255cf7358fac32c8ac6757857e7acfa89a7963241a9e96a9e085c9cec8201f980b66b98c077f40d672b3005f788ed60e761b90c
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

**Payload CBOR (163 bytes):**
```
aa00010150019471f80000700080000000000000a0020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a04820158208139770ea87d175f56a35466c34c7ecccb8d
8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
031200
```

**Signature (64 bytes):**
```
795cfa2f604317b61c770a2e1595968be9fc9ff77846b9c65f1e40570eb17344b62d8929ddc1ac1af2a40f1f9a0d817057f2a397a609afeb581e24ca1cb79f0c
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

**Payload CBOR (206 bytes):**
```
ab00010150019471f80000700080000000000000a1020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e6f2f646174612f7265706f7274732f2a0482015820ed4928c628d1c2c6eae9
0338905995612959273a5c63f93636c14614ac8737d105820158208139770ea8
7d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394061a659200
80071a65920e9008030998200000000000000000000000000000000000000000
0000000000000000000000001201
```

**Signature (64 bytes):**
```
65cc4fc544c331ba682404a444367d644ebd4438a8e731eb84c0f1d0ba57595568e94fb3053a20d22727770414f5b7c9f2f7c32841801ec93c07bd842ac9490b
```

**Parent Hash Comparison:**

| Field | Value |
|-------|-------|
| Correct parent_hash | `9b60b7ae1a679d990d77502db310315455d3b624f9a616f5bb7f34bccbd37914` |
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

**Payload CBOR (163 bytes):**
```
aa00010150019471f80000700080000000000000b0020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a04820158208139770ea87d175f56a35466c34c7ecccb8d
8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
031200
```

**Signature (64 bytes):**
```
221a7bcbe2e9427338c316262d2322edfcc59340814447b0deaf5556dd11ff764ca48a4166aedafa21da6a52e22d9b0b20392ad425c10eaad4221157f730e903
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
| Parent Hash | `ee45364a444eb40f34b017d8584b435629de258208624a8de4fce6d3ebd9a3c9` |

**Payload CBOR (235 bytes):**
```
ab00010150019471f80000700080000000000000b1020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e6f2f646174612f7265706f7274732f2a0482015820ed4928c628d1c2c6eae9
0338905995612959273a5c63f93636c14614ac8737d105820158208139770ea8
7d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394061a659200
80071a65921ca0080309982018ee18451836184a1844184e18b40f183418b017
18d81858184b18431856182918de18251882081862184a188d18e418fc18e618
d318eb18d918a318c91201
```

**Signature (64 bytes):**
```
4cc40a8fb7776042dbc0eef0a4833c92b678b3da405d249c58226db34c26e1905f86f2e73e98d891e93d0cd79a1ab3b15d811b4d4cf5f3f6a6d06e8030e8f705
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

**Payload CBOR (163 bytes):**
```
aa00010150019471f80000700080000000000000c0020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a04820158208139770ea87d175f56a35466c34c7ecccb8d
8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
031200
```

**Signature (64 bytes):**
```
0038e4fc6d200a00e3a39987a0e172d8086812331da17e911e0fc2699bde94a7e413ad1b7a2ea1886627d822535ab3f469cd43e7f28e4c7c476bede22dcc8a05
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

**Payload CBOR (163 bytes):**
```
aa00010150019471f80000700080000000000000c0020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a04820158208139770ea87d175f56a35466c34c7ecccb8d
8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
031200
```

**Signature (64 bytes):**
```
8e08644ea750b3b09f8593b05fbb9f4d2c1c0b37f07dfe097fb58952ba279228eede73926d6d4d2796a2fdf69b28501aaa75439ebcbbd2adb9efd0f04bd84c0e
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

---

## A.15 Issuer Constraint Violation

**Scenario:** Issuer warrant defines bounds, child exceeds them.

**A.15 Issuer Warrant**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f80000700080000000000000d0` |
| Type | Issuer |
| Depth | 0 |
| Max Depth | 5 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (168 bytes):**
```
ad00010150019471f80000700080000000000000d0020103a004820158208139
770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940582
0158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4
0f6f5c061a65920080071a65920e9008050b8169726561645f66696c650d030e
a16b636f6e73747261696e7473a164706174688202a1677061747465726e672f
646174612f2a1200
```

**Signature (64 bytes):**
```
72609ed0e640d1ad17fa392ccc8e6457802cfa50c3b29dd20aba5c9eac63c6a4dcaf1e101de97ae2411d2f4a6a9e5b88460019d0423b30a7e2531df828e5ce0e
```

**Child Warrant (Invalid - Constraints Outside Bounds):**

**A.15 Invalid Child**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f80000700080000000000000d1` |
| Type | Execution |
| Depth | 1 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Parent Hash | `650fa5f9851339e6cba71f5d8384ca826fc4e9038395d127e960e0ec837e8003` |

**Payload CBOR (228 bytes):**
```
ab00010150019471f80000700080000000000000d1020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688201a16576616c75656b
2f6574632f7061737377640482015820ed4928c628d1c2c6eae9033890599561
2959273a5c63f93636c14614ac8737d105820158208139770ea87d175f56a354
66c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394061a65920080071a65920e
90080309982018650f18a518f9188513183918e618cb18a7181f185d18831884
18ca1882186f18c418e9031883189518d1182718e9186018e018ec1883187e18
80031201
```

**Signature (64 bytes):**
```
7f1c56d81b94eedd32061bcb56833e6ce00a8db1e2b95d9695e05c6ed744be2397e7746a6eb3faac9958ba0535bd568e5d2f31f302f40168d7dca730469d500e
```

**Expected:** Verification MUST fail with `constraint_violation` (Child constraints not subset of Parent bounds).

---

## A.16 Self-Issuance Violation

**Scenario:** Holder delegates execution warrant to themselves (Privilege Escalation / Separation of Duties).

**A.16 Invalid Self-Issuance**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f80000700080000000000000e0` |
| Type | Execution |
| Depth | 1 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Parent Hash | `705e79416823ef819a08e0c59feccb5d4baed4a7ebcaca290b014112cec5fc64` |

**Payload CBOR (226 bytes):**
```
ab00010150019471f80000700080000000000000e0020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a04820158208139770ea87d175f56a35466c34c7ecccb8d
8a91b4ee37a25df60f5b8fc9b39405820158208139770ea87d175f56a35466c3
4c7ecccb8d8a91b4ee37a25df60f5b8fc9b394061a65920080071a65920e9008
030998201870185e187918411868182318ef1881189a0818e018c5189f18ec18
cb185d184b18ae18d418a718eb18ca18ca18290b0118411218ce18c518fc1864
1201
```

**Signature (64 bytes):**
```
225a01c889e03f912e768a9d0c2431bdce3cac5091d1f01dd45f1105a8127fdea28c039807f878d63af664c4b20aedf7a1a14618f87bf1f1a466f9f03dc27103
```

**Expected:** Verification MUST fail with `self_issuance` error.

---

## A.17 Clearance Violation

**Scenario:** Child attempts to increase clearance level.

**A.17 Parent (Clearance=5)**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f80000700080000000000000f0` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (165 bytes):**
```
ab00010150019471f80000700080000000000000f0020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a04820158208139770ea87d175f56a35466c34c7ecccb8d
8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
0311051200
```

**Signature (64 bytes):**
```
8cf891507b235cd48494d35250275063d3d22b119c6eabedc14378503ef288d419b50de5287dbca48d0a3dfebe5709bf26e974f4e1b3fb9ace2d245652174e06
```

**A.17 Invalid Child (Clearance=6)**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f80000700080000000000000f1` |
| Type | Execution |
| Depth | 1 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Parent Hash | `a34797bde49e2afc3ca60b623eb75b6c1a4f5188b405d5632565a277a16cf120` |

**Payload CBOR (230 bytes):**
```
ac00010150019471f80000700080000000000000f1020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a0482015820ed4928c628d1c2c6eae90338905995612959
273a5c63f93636c14614ac8737d105820158208139770ea87d175f56a35466c3
4c7ecccb8d8a91b4ee37a25df60f5b8fc9b394061a65920080071a65920e9008
0309982018a31847189718bd18e4189e182a18fc183c18a60b1862183e18b718
5b186c181a184f1851188818b40518d518631825186518a2187718a1186c18f1
182011061201
```

**Signature (64 bytes):**
```
7c0e1f803397c26afeaf1bceaec2fce0beef611a5d34745f903e49f8eb811a0b58f5a68d43c114e1ebc82ab04fe2bc6ae32cd5b58c2e3de0da354974dc3b4d02
```

**Expected:** Verification MUST fail with `clearance_monotonicity_violated`.

---

## A.18 Multi-sig Configuration

**Scenario:** Warrant with required approvers.

**A.18 Multi-sig**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000000018` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (239 bytes):**
```
ac00010150019471f8000070008000000000000018020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a04820158208139770ea87d175f56a35466c34c7ecccb8d
8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
030f8282015820ed4928c628d1c2c6eae90338905995612959273a5c63f93636
c14614ac8737d182015820ca93ac1705187071d67b83c7ff0efe8108e8ec4530
575d7726879333dbdabe7c10011200
```

**Signature (64 bytes):**
```
cbf183a10dec415c4ce5210e44736f7faac63cc93107cd0d648ededc9dc9e06f6aa1a68bcdb8186ef2032a1dc17efa9434b2915c41954bd0dd1a564a83313101
```

Verifiers MUST enforce approvals from `worker` or `worker2` before execution.

---

## A.19 Constraint Type Coverage

Byte-exact test vectors for constraint type validation.

### A.19.1 Range Constraint

**A.19.1 Range**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000001901` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (191 bytes):**
```
aa00010150019471f8000070008000000000001901020003a1686170695f6361
6c6ca16b636f6e73747261696e7473a165636f756e748203a4636d696ef90000
636d6178f956406d6d696e5f696e636c7573697665f56d6d61785f696e636c75
73697665f50482015820ed4928c628d1c2c6eae90338905995612959273a5c63
f93636c14614ac8737d105820158208a88e3dd7409f195fd52db2d3cba5d72ca
6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008031200
```

**Signature (64 bytes):**
```
ee3f39a047b693d297097d6d7b9798eff5b6b933ec2e13c11b359166db5350b1f7a2251342e17f230b581567f474a72fef2e20deb56a6698dfb6d8f37d5cab0f
```

| Valid Input | `count = 50.0` |
| Invalid Input | `count = 150.0` |

**Expected:** Valid input MUST succeed, invalid input MUST fail with constraint violation.

### A.19.2 OneOf Constraint

**A.19.2 OneOf**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000001902` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (170 bytes):**
```
aa00010150019471f8000070008000000000001902020003a1666465706c6f79
a16b636f6e73747261696e7473a163656e768204a16676616c75657382677374
6167696e676a70726f64756374696f6e0482015820ed4928c628d1c2c6eae903
38905995612959273a5c63f93636c14614ac8737d105820158208a88e3dd7409
f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080
071a65920e9008031200
```

**Signature (64 bytes):**
```
46fa8f8ac799a69d75799932ce23680d089c1b8d5f59eedabfe64c1e6d6542f0b49a7372ff4cf1730b65d44eeb2346883469629892d3a4ffe81f79c1494e2a02
```

| Valid Input | `env = "staging"` |
| Invalid Input | `env = "development"` |

**Expected:** Valid input MUST succeed, invalid input MUST fail with constraint violation.

### A.19.3 CIDR Constraint

**A.19.3 CIDR**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000001903` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (153 bytes):**
```
aa00010150019471f8000070008000000000001903020003a167636f6e6e6563
74a16b636f6e73747261696e7473a162697082086a31302e302e302e302f3804
82015820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614
ac8737d105820158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d9412
1bf3748801b40f6f5c061a65920080071a65920e9008031200
```

**Signature (64 bytes):**
```
58b6d148f5de312064bdf21b77ec8b10ed5d76aa6e5f4ea4d0aabc0254b33135b1e830fb8ea5934b0ab103a6e9fa483be442d20b5f062852826498c0942e7b03
```

| Valid Input | `ip = "10.1.2.3"` |
| Invalid Input | `ip = "192.168.1.1"` |

**Expected:** Valid input MUST succeed, invalid input MUST fail with constraint violation.

---

## A.20 Proof-of-Possession Failures

### A.20.1 PoP with Wrong Holder Key

**A.20.1**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002001` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (163 bytes):**
```
aa00010150019471f8000070008000000000002001020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a0482015820ed4928c628d1c2c6eae90338905995612959
273a5c63f93636c14614ac8737d105820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
031200
```

**Signature (64 bytes):**
```
dd95d46b38cd23d62caa4b3e588eade7b9fd87b5361b5b53afbf8029bb4fa0432cd1cdadeee84fec67e08b185a954fddcd4cca9100423af1ccb5093462aae30f
```

| Holder | Worker |
| PoP Signer (Invalid) | Attacker |

**Invalid PoP Signature (signed by Attacker):**
```
183a5bd8faaf1c8a523cdb804f26e8276bef7c8617446cacc0be8b33fb4a8a1311e90670e7b080001b5c50e5947acc53d442858da591c15271e3ae143e8d5f06
```

**Valid PoP Signature (signed by Holder/Worker):**
```
3062d9783c8667de1868d96ac33b25fbc1e140c3e3213423abf4811065e20d500834f3d9332d562c27efd249ea7a43aac0d3430cc84fefad7b0fc248d9cf8200
```

**Expected:** Invalid PoP MUST fail with signature error.

---

## A.21 Signed Approval (Multi-sig)

### A.21.1 Valid 2-of-3 Multi-sig

**Additional Key Material:**

| Role | Seed | Public Key |
|------|------|------------|
| Approver1 | `1111...11` (32×0x11) | `d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737` |
| Approver2 | `1212...12` (32×0x12) | `204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21` |
| Approver3 | `1313...13` (32×0x13) | `66cd608b928b88e50e0efeaa33faf1c43cefe07294b0b87e9fe0aba6a3cf7633` |

**A.21.1**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002101` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (275 bytes):**
```
ac00010150019471f8000070008000000000002101020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a0482015820ed4928c628d1c2c6eae90338905995612959
273a5c63f93636c14614ac8737d105820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
030f8382015820204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e8
2caba867877c218201582066cd608b928b88e50e0efeaa33faf1c43cefe07294
b0b87e9fe0aba6a3cf763382015820d04ab232742bb4ab3a1368bd4615e4e6d0
224ab71a016baf8520a332c977873710021200
```

**Signature (64 bytes):**
```
030ddfbe8a7301b1a39e82f5d902cc9960d02dc72439544c41693be4514ba8b82a7576c31298ceab2c6b555e53ce06451970f71cc2f4e3f85ed307e6ce358207
```

| Required Approvers | 3 |
| Min Approvals | 2 |

**Expected:** Authorization MUST succeed with 2+ valid approvals from listed approvers.

### A.21.2 Insufficient Approvals

**A.21.2**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002102` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (239 bytes):**
```
ac00010150019471f8000070008000000000002102020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a0482015820ed4928c628d1c2c6eae90338905995612959
273a5c63f93636c14614ac8737d105820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
030f8282015820204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e8
2caba867877c2182015820d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a
016baf8520a332c977873710021200
```

**Signature (64 bytes):**
```
85e9e47d9950e874facf7717eec98771ab7b495eb18612858e6ac9247911a78b1e80b686b98d709964c94814e3b3213879f12082dff5a7f6719ab64628c41a06
```

| Required Approvers | 2 |
| Min Approvals | 2 |
| Provided Approvals | 1 (only Approver1) |

**Expected:** Authorization MUST fail with insufficient approvals.

---

## A.22 Cascading Revocation

**A.22 Root**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002200` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (163 bytes):**
```
aa00010150019471f8000070008000000000002200020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a04820158208139770ea87d175f56a35466c34c7ecccb8d
8a91b4ee37a25df60f5b8fc9b39405820158208a88e3dd7409f195fd52db2d3c
ba5d72ca6709bf1d94121bf3748801b40f6f5c061a65920080071a65920e9008
031200
```

**Signature (64 bytes):**
```
393884653ab620954651107c73eb90223d868d403850ec092ac8a5c08894416040b27381b1b149f5cb3d7bc5efc8dadda425c247aa220b3990656138c643b809
```

**A.22 Child**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002201` |
| Type | Execution |
| Depth | 1 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Parent Hash | `a5806efffd9e7846a9ddd6919e7848d55bfd5d5d5a839cfe02238d9ff4906a30` |

**Payload CBOR (229 bytes):**
```
ab00010150019471f8000070008000000000002201020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688202a167706174746572
6e672f646174612f2a0482015820ed4928c628d1c2c6eae90338905995612959
273a5c63f93636c14614ac8737d105820158208139770ea87d175f56a35466c3
4c7ecccb8d8a91b4ee37a25df60f5b8fc9b394061a65920080071a65920e9008
0309982018a51880186e18ff18fd189e1878184618a918dd18d61891189e1878
184818d5185b18fd185d185d185a1883189c18fe021823188d189f18f4189018
6a18301201
```

**Signature (64 bytes):**
```
d5b4237ec474608233c4c3bf5680a8111bf8e186cce1b30dc97c6c810627eee92323a8965ab67a9faa47c4e02cdbb2471ab91e9d1328a691aa2c5cdf768df70b
```

**Revocation Scenario:**

| Revoked Warrant | Child (`tnu_wrt_019471f8000070008000000000002201`) |

**Expected:** Chain verification MUST fail when child warrant is revoked.

---

## A.23 Session Mismatch

**A.23 Root (session_id=sess-abc)**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002300` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (183 bytes):**
```
ab00010150019471f8000070008000000000002300020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688210f604820158208139
770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940582
0158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4
0f6f5c061a65920080071a65920e9008030aa17074656e756f2e73657373696f
6e5f6964881873186518731873182d1861186218631200
```

**Signature (64 bytes):**
```
2f1743195b81b1fea73a140d6037bccbc12660e5ec20bbd4cfb996e7ca28357208e58faa568ed3985e9265fd4944cbe84c068996f991cf35a75b74b5910e9906
```

**A.23 Root (no session_id)**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002301` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (147 bytes):**
```
aa00010150019471f8000070008000000000002301020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688210f604820158208139
770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b3940582
0158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4
0f6f5c061a65920080071a65920e9008031200
```

**Signature (64 bytes):**
```
9232a1f42d85ebcec2594c9153e4d054bbbfa34f47bc75fd514e72f105a615ffda4729187d6e0508afaa5ff8da3a82a43aa57203b50f05674fe7c607146a3808
```

**A.23 Child (inherited no session)**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002302` |
| Type | Execution |
| Depth | 1 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| Parent Hash | `e0ecb74e7becdd5eb1eb281d5e50b3df4dafe503e0f4cf6632de1d894e9b1943` |

**Payload CBOR (213 bytes):**
```
ab00010150019471f8000070008000000000002302020003a169726561645f66
696c65a16b636f6e73747261696e7473a164706174688210f60482015820ed49
28c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10582
0158208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8f
c9b394061a65920080071a65920e90080309982018e018ec18b7184e187b18ec
18dd185e18b118eb1828181d185e185018b318df184d18af18e50318e018f418
cf1866183218de181d1889184e189b181918431201
```

**Signature (64 bytes):**
```
ebe0aeaa91e09f9d5f89cb758561e2243ba89cb41904b698958333e8f195c81c90473a192e72dc3e6ac342fd2f5dc475450f84558847c6b4e620d291d5fc9b0c
```

**Session Mismatch Scenario:**

Mix Root (with session) and Child (without session) in a chain:

| Root | `tnu_wrt_019471f8000070008000000000002300` (session_id=sess-abc) |
| Child | `tnu_wrt_019471f8000070008000000000002302` (session_id=None) |

**Expected:**
- `verify_chain()`: MAY succeed (session check optional)
- `verify_chain_strict()`: MUST fail with session mismatch error

> [!NOTE]
> `session_id` is inherited during attenuation and cannot be changed.
> Mismatch occurs when mixing warrants from different session contexts.

---

## A.24 SignedApproval Envelope

Complete wire format for human-in-the-loop approval.

### SignedApproval Structure

| Field | Type | Description |
|-------|------|-------------|
| `approval_version` | u8 | Envelope version (1) |
| `payload` | bytes | CBOR-encoded ApprovalPayload |
| `approver_key` | [u8; 32] | Ed25519 public key |
| `signature` | [u8; 64] | Ed25519 signature |

### ApprovalPayload

| Field | Value |
|-------|-------|
| `version` | 1 |
| `request_hash` | `586ebf1bfceaa54616f1bcf0d90bc7729a1c2b9a512c175bd65f98f6ef1443d1` |
| `nonce` | `a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8` |
| `external_id` | `arn:aws:iam::123456789012:user/security-admin` |
| `approved_at` | `1704067200` |
| `expires_at` | `1704070800` |

**ApprovalPayload CBOR (172 bytes):**
```
a66776657273696f6e016c726571756573745f686173685820586ebf1bfceaa5
4616f1bcf0d90bc7729a1c2b9a512c175bd65f98f6ef1443d1656e6f6e636550
a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b86b65787465726e616c5f6964782d6172
6e3a6177733a69616d3a3a3132333435363738393031323a757365722f736563
75726974792d61646d696e6b617070726f7665645f61741a659200806a657870
697265735f61741a65920e90
```

**Signing Preimage:**
```
b"tenuo-approval-v1" || 0x01 || payload_bytes
```

**Approver Signature (64 bytes):**
```
43681e09a5ecdd8392eb157f1d8dfe744f37f28030725a1f5c84ad41c57574a1d768ba733e8e4052934c96e90b49fb4cfe29d600f4af1afb1b68ea634d6f290a
```

**Complete SignedApproval Envelope (324 bytes):**
```
a470617070726f76616c5f76657273696f6e01677061796c6f616458aca66776
657273696f6e016c726571756573745f686173685820586ebf1bfceaa54616f1
bcf0d90bc7729a1c2b9a512c175bd65f98f6ef1443d1656e6f6e636550a1a2a3
a4a5a6a7a8b1b2b3b4b5b6b7b86b65787465726e616c5f6964782d61726e3a61
77733a69616d3a3a3132333435363738393031323a757365722f736563757269
74792d61646d696e6b617070726f7665645f61741a659200806a657870697265
735f61741a65920e906c617070726f7665725f6b65795820d04ab232742bb4ab
3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737697369676e617475
7265584043681e09a5ecdd8392eb157f1d8dfe744f37f28030725a1f5c84ad41
c57574a1d768ba733e8e4052934c96e90b49fb4cfe29d600f4af1afb1b68ea63
4d6f290a
```

---

## A.22.b SignedRevocationList (SRL)

Complete wire format for revocation list.

### SrlPayload

| Field | Value |
|-------|-------|
| `revoked_ids` | `["tnu_wrt_019471f8000070008000000000002201"]` |
| `version` | 1 |
| `issued_at` | `1704067200` |
| `issuer` | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**SrlPayload CBOR (148 bytes):**
```
a46b7265766f6b65645f696473817828746e755f7772745f3031393437316638
3030303037303030383030303030303030303030323230316776657273696f6e
01696973737565645f61741a65920080666973737565729820188a188818e318
dd18740918f1189518fd185218db182d183c18ba185d187218ca18670918bf18
1d189412181b18f3187418880118b40f186f185c
```

**Signing Preimage:**
```
b"tenuo-srl-v1" || payload_bytes
```

**Control Plane Signature (64 bytes):**
```
b82234fcc8c4dfd49f150cb3fc26e7ebe5f49dedbd9d2c09761a761fa74fcf1d8dbf79533b1031bee8c31f1b234fa179372b55a90e4bf359bc64a02477e74f01
```

**Complete SignedRevocationList (233 bytes):**
```
a2677061796c6f6164a46b7265766f6b65645f696473817828746e755f777274
5f30313934373166383030303037303030383030303030303030303030323230
316776657273696f6e01696973737565645f61741a6592008066697373756572
9820188a188818e318dd18740918f1189518fd185218db182d183c18ba185d18
7218ca18670918bf181d189412181b18f3187418880118b40f186f185c697369
676e61747572655840b82234fcc8c4dfd49f150cb3fc26e7ebe5f49dedbd9d2c
09761a761fa74fcf1d8dbf79533b1031bee8c31f1b234fa179372b55a90e4bf3
59bc64a02477e74f01
```

---

## A.25 Additional Constraint Types

Byte-exact test vectors for remaining constraint types.

### A.25.1 UrlSafe Constraint

**A.25.1 UrlSafe**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002501` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (281 bytes):**
```
aa00010150019471f8000070008000000000002501020003a16c687474705f72
657175657374a16b636f6e73747261696e7473a16375726c8212a86773636865
6d65738264687474706568747470736d616c6c6f775f646f6d61696e73f66b61
6c6c6f775f706f727473f66d626c6f636b5f70726976617465f56e626c6f636b
5f6c6f6f706261636bf56e626c6f636b5f6d65746164617461f56e626c6f636b
5f7265736572766564f573626c6f636b5f696e7465726e616c5f746c6473f404
82015820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614
ac8737d105820158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d9412
1bf3748801b40f6f5c061a65920080071a65920e9008031200
```

**Signature (64 bytes):**
```
3534a5c9a06d23e9ca7f29147f7d0ae4c0477132d707000609c06011f6239c6973ad95074504987a5f7c6930712e22f67c30fd2528c71cab280181a38969ab04
```

| Valid Input | `url = "https://api.example.com/data"` |
| Invalid Input | `url = "http://169.254.169.254/"` (AWS metadata) |

**Expected:** SSRF-safe URLs succeed, internal/metadata URLs fail.

### A.25.2 Subpath Constraint

**A.25.2 Subpath**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002502` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (204 bytes):**
```
aa00010150019471f8000070008000000000002502020003a16a77726974655f
66696c65a16b636f6e73747261696e7473a164706174688211a364726f6f7475
2f686f6d652f6167656e742f776f726b73706163656e636173655f73656e7369
74697665f56b616c6c6f775f657175616cf50482015820ed4928c628d1c2c6ea
e90338905995612959273a5c63f93636c14614ac8737d105820158208a88e3dd
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592
0080071a65920e9008031200
```

**Signature (64 bytes):**
```
f2207123d92f18f295d02865289b12d54f3133982da274dc50d516808c6d55ae51beed8050cb83d9563babc2bdb9729830dd0a423be5199d82a720dec1350606
```

| Valid Input | `path = "/home/agent/workspace/file.txt"` |
| Invalid Input | `path = "/home/agent/workspace/../../../etc/passwd"` |

**Expected:** Contained paths succeed, traversal attacks fail.

### A.25.3 Contains Constraint

**A.25.3 Contains**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002503` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (172 bytes):**
```
aa00010150019471f8000070008000000000002503020003a1666465706c6f79
a16b636f6e73747261696e7473a16474616773820aa168726571756972656482
68617070726f7665646872657669657765640482015820ed4928c628d1c2c6ea
e90338905995612959273a5c63f93636c14614ac8737d105820158208a88e3dd
7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c061a6592
0080071a65920e9008031200
```

**Signature (64 bytes):**
```
a061b3c3a362b262d0821baaa425e2055044cbe7318d0db631bc7dd2d7e655a2099164d9efc3b74cfc83e95e38ea71e83834a63653ef9e968c8a39e9633bcf05
```

| Valid Input | `tags = ["approved", "reviewed", "urgent"]` |
| Invalid Input | `tags = ["approved", "urgent"]` (missing "reviewed") |

**Expected:** Lists containing required values succeed.

### A.25.4 Subset Constraint

**A.25.4 Subset**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002504` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (187 bytes):**
```
aa00010150019471f8000070008000000000002504020003a16f7365745f7065
726d697373696f6e73a16b636f6e73747261696e7473a16b7065726d69737369
6f6e73820ba167616c6c6f7765648364726561646577726974656664656c6574
650482015820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c1
4614ac8737d105820158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d
94121bf3748801b40f6f5c061a65920080071a65920e9008031200
```

**Signature (64 bytes):**
```
dd676028ac2604e89ce5747283065a82c2fb5403a6d7237956dc33ad708660f61cbb563c1ec31526a5b771aa98801ae68d6cd15668817e0a33a9446621b0e901
```

| Valid Input | `permissions = ["read", "write"]` |
| Invalid Input | `permissions = ["read", "admin"]` |

**Expected:** Subset of allowed values succeeds, extras fail.

### A.25.5 UrlPattern Constraint

**A.25.5 UrlPattern**

| Field | Value |
|-------|-------|
| ID | `tnu_wrt_019471f8000070008000000000002505` |
| Type | Execution |
| Depth | 0 |
| Max Depth | 3 |
| Issued At | `1704067200` |
| Expires At | `1704070800` |
| Holder | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| Issuer | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |

**Payload CBOR (179 bytes):**
```
aa00010150019471f8000070008000000000002505020003a1686170695f6361
6c6ca16b636f6e73747261696e7473a168656e64706f696e748209781c687474
70733a2f2f6170692e6578616d706c652e636f6d2f76312f2a0482015820ed49
28c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d10582
0158208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b4
0f6f5c061a65920080071a65920e9008031200
```

**Signature (64 bytes):**
```
d29d9491f00b997d28bd3ca8fde1b82657215295053a93303ba541d64f49924f5475dee1f047d2f5bfadea7a37a5ba56a05f4b62d0a604a077ab1b54c8df7503
```

| Valid Input | `endpoint = "https://api.example.com/v1/users"` |
| Invalid Input | `endpoint = "https://evil.com/api"` |

**Expected:** URLs matching pattern succeed.
