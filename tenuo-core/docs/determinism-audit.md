# Determinism Audit (Task 1)

Scope: `tenuo-core` call paths rooted at:

- `Warrant::sign`
- `Warrant::dedup_key`
- `Authorizer::authorize_one`
- `Authorizer::authorize_one_with_pop_args`
- `Authorizer::check_chain`
- `Authorizer::check_chain_with_pop_args`
- `py_compute_request_hash`
- `evaluate_approval_gates`
- `encode_warrant_stack` / `decode_warrant_stack_base64` (PyO3 entry points)
- `py_to_constraint_value` (PyDict -> `ConstraintValue` path)

Method: inspected map/set usage (`HashMap`, `HashSet`, and unordered iteration via `.iter()`, `.keys()`, `.values()`, `.into_iter()`) in each root and downstream call path until bytes/strings/return values leave the function.

## Findings

| Finding ID | File:Line | Function / Path | Iterated structure | Output sink | Severity | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| finding-pop-sign-sort | `tenuo-core/src/warrant.rs:1165` | `Warrant::sign` -> `sign_with_timestamp` | `HashMap<String, ConstraintValue>` via `args.iter()` | CBOR challenge bytes used as PoP signed preimage | high | Immediately canonicalized by `sort_by_key` before serialization (`:1166`), so output is deterministic. |
| finding-pop-verify-sort | `tenuo-core/src/warrant.rs:1084` | `Authorizer::*` -> `Warrant::authorize_with_pop_args_and_config` -> `verify_pop` | `HashMap<String, ConstraintValue>` via `args.iter()` | CBOR challenge bytes used to verify PoP signature | high | Immediately canonicalized by `sort_by_key` before serialization (`:1085`). |
| finding-dedup-sort | `tenuo-core/src/warrant.rs:1187` | `Warrant::dedup_key` | `HashMap<String, ConstraintValue>` via `args.iter()` | CBOR payload bytes hashed for dedup key output string | high | Immediately canonicalized by `sort_by_key` before serialization (`:1188`). |
| finding-request-hash-sort | `tenuo-core/src/approval.rs:398` | `py_compute_request_hash` -> `compute_request_hash` -> `canonical_tool_args_cbor` | `HashMap<String, ConstraintValue>` via `args.iter()` into `BTreeMap` | CBOR bytes fed into request hash | high | Canonicalization boundary is explicit (`BTreeMap` materialization) before hashing. |
| finding-py-sign-ingest | `tenuo-core/src/python.rs:4172` | `py_to_constraint_value` path via `PyWarrant.sign` | Python `PyDict` iteration into Rust `HashMap` | Intermediate map passed to `Warrant::sign_with_timestamp` | low | Dict iteration order is not used directly for bytes; downstream PoP signing re-sorts keys in Rust (`warrant.rs:1165-1166`). |
| finding-py-dedup-ingest | `tenuo-core/src/python.rs:4198` | `py_to_constraint_value` path via `PyWarrant.dedup_key` | Python `PyDict` iteration into Rust `HashMap` | Intermediate map passed to `Warrant::dedup_key` | low | Downstream dedup path re-sorts keys (`warrant.rs:1187-1188`). |
| finding-py-request-hash-ingest | `tenuo-core/src/python.rs:4914` | `py_compute_request_hash` | Python `PyDict` iteration into Rust `HashMap` | Intermediate map passed to hash canonicalizer | low | Downstream request hash path canonicalizes via `BTreeMap` (`approval.rs:398`). |
| finding-py-authorize-one-ingest | `tenuo-core/src/python.rs:5476` | `PyAuthorizer.authorize_one` -> `Authorizer::authorize_one` | Python `PyDict` iteration into Rust `HashMap` | Intermediate args map for chain checks | low | PoP/hash-sensitive downstream paths canonicalize before byte production (`warrant.rs:1084`, `approval.rs:398`). |
| finding-py-check-chain-ingest | `tenuo-core/src/python.rs:5585` | `PyAuthorizer.check_chain` -> `Authorizer::check_chain` | Python `PyDict` iteration into Rust `HashMap` | Intermediate args map for chain checks | low | Delegates to split-view path; PoP/hash-sensitive sinks canonicalize. |
| finding-py-authorize-split-pop-ingest | `tenuo-core/src/python.rs:5645` | `PyAuthorizer.authorize_one_with_pop_args` | Python `PyDict` (`pop_args`) into Rust `HashMap` | Intermediate pop args map for PoP/hash paths | low | Downstream PoP/hash sinks canonicalize (`warrant.rs:1084`, `approval.rs:398`). |
| finding-py-authorize-split-constraint-ingest | `tenuo-core/src/python.rs:5652` | `PyAuthorizer.authorize_one_with_pop_args` | Python `PyDict` (`constraint_args`) into Rust `HashMap` | Constraint matching return path | low | Constraint checks are key lookups / ordered constraint traversal; no byte sink from map iteration order on this path. |
| finding-py-check-split-pop-ingest | `tenuo-core/src/python.rs:5716` | `PyAuthorizer.check_chain_with_pop_args` | Python `PyDict` (`pop_args`) into Rust `HashMap` | Intermediate pop args map for PoP/hash paths | low | Downstream PoP/hash sinks canonicalize (`warrant.rs:1084`, `approval.rs:398`). |
| finding-py-check-split-constraint-ingest | `tenuo-core/src/python.rs:5723` | `PyAuthorizer.check_chain_with_pop_args` | Python `PyDict` (`constraint_args`) into Rust `HashMap` | Constraint matching return path | low | Same reasoning as `finding-py-authorize-split-constraint-ingest`. |

## Root-by-root notes

### `Warrant::sign`

- Uses `HashMap::iter` then explicit key sort before CBOR serialization.
- No unordered map/set iteration reaches signed bytes.

### `Warrant::dedup_key`

- Uses `HashMap::iter` then explicit key sort before CBOR serialization and SHA-256.
- No unordered map/set iteration reaches dedup hash bytes.

### `Authorizer::authorize_one` / `authorize_one_with_pop_args` / `check_chain` / `check_chain_with_pop_args`

- Root methods are wrappers/delegators and do not themselves iterate unordered maps/sets into output sinks.
- Downstream PoP and request-hash paths are covered by `finding-pop-verify-sort` and `finding-request-hash-sort`.

### `py_compute_request_hash`

- Ingests `PyDict` via iteration into `HashMap`, then canonicalizes in `approval::canonical_tool_args_cbor` before hashing.

### `evaluate_approval_gates`

- Iteration is over `ToolApprovalGate.args: BTreeMap<...>` (`tenuo-core/src/approval_gate.rs:379`), which is ordered.
- `args` is a `HashMap` but only accessed by key lookup (`args.get(arg_name)`, `:380`), not iterated.
- No unordered iteration reaches return value from this function.

### `encode_warrant_stack` / `decode_warrant_stack_base64`

- PyO3 wrappers (`tenuo-core/src/python.rs:6095`, `:6124`) operate on `Vec<Warrant>` and call `wire::decode_stack` / `wire::encode_stack` (`tenuo-core/src/wire.rs:184`, `:192`).
- No `HashMap`/`HashSet` iteration in these stack entry points.

### `py_to_constraint_value` (PyDict -> `ConstraintValue` conversion path)

- `py_to_constraint_value` itself does not iterate maps; callers ingest `PyDict` and place entries into `HashMap` (findings above).
- In all audited call paths that reach hashes/signatures, deterministic ordering is enforced at serialization/hash boundaries.

## Counts

- High: 4
- Medium: 0
- Low: 9

Escalation thresholds not triggered:

- High findings > 20: **no**
- Generic PyErr escapes > 40: not part of Task 1
