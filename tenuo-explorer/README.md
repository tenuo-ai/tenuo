# Tenuo Explorer

🔐 **WASM-powered warrant decoder & authorization playground**

A browser-based tool for inspecting Tenuo warrants, visualizing constraints, and simulating authorization checks—all running locally in WebAssembly. No data leaves your browser.

## Live Demo

Visit: `https://tenuo.dev/explorer/` (or run locally)

## Features

### 🔍 Decoder Mode
Paste any base64-encoded warrant and instantly see:
- **Warrant ID** and issuer fingerprint
- **Authorized tools** and their constraints
- **Expiration timeline** with live countdown
- **Holder** public key

### 💻 Code Generator — Learn the API by Example
**Don't know how to write the code?** Decode any warrant and click **Code** to get the exact `Warrant.mint_builder()` syntax to recreate it.

This is the fastest way to learn Tenuo's API:
1. Decode a warrant (yours or a sample)
2. Click the **Code** tab
3. Copy working Python or Rust code

**What it generates:**
- Key generation (`SigningKey.generate()`)
- Builder pattern with all capabilities from the warrant
- Authorization check with PoP signature
- `BoundWarrant` usage example
- Serialization to base64

The generated code uses the **actual TTL and constraints** from your warrant—not hardcoded placeholders.

**Constraint Type Support:**

| Constraint | Decode | Code Gen | Format |
|------------|--------|----------|--------|
| Pattern | ✅ | ✅ | `{ pattern: "docs/*" }` |
| Exact | ✅ | ✅ | `{ exact: "USD" }` |
| Range | ✅ | ✅ | `{ min: 0, max: 100 }` or `{ range: "0-100" }` |
| OneOf | ✅ | ✅ | `{ oneof: ["a", "b"] }` |
| NotOneOf | ✅ | ✅ | `{ notoneof: ["x"] }` |
| AnyOf | ✅ | ✅ | `{ anyof: ["a*", "b*"] }` |
| Regex | ✅ | ✅ | `{ regex: "^[a-z]+$" }` |
| Contains | ✅ | ✅ | `{ contains: "substring" }` |
| Cidr | ✅ | ✅ | `{ cidr: "10.0.0.0/8" }` |
| Wildcard | ✅ | ✅ | `{ wildcard: "user_*" }` |
| UrlPattern | ✅ | ✅ | `{ url_pattern: "https://*.example.com/*" }` |
| CEL | ✅ | ❌ | Shows as comment (advanced expressions) |
| All/Any/Not | ✅ | ❌ | Shows as comment (composite constraints) |
| Subset | ✅ | ❌ | Shows as comment (set operations) |

Constraints marked ❌ for Code Gen will still decode and display correctly—they just won't generate copyable Python/Rust code.

### 📤 Shareable Deep Links
Found a suspicious warrant? Click **Share** to generate a URL containing the warrant state. Send it to a colleague so they can debug the exact same warrant without copy-pasting base64.

Example: `tenuo.dev/explorer?s=eyJ3YXJyYW50...`

Great for:
- Debugging issues with your team
- Sharing examples in documentation
- Bug reports ("here's the warrant that failed")

### 🛡️ Authorization Simulator
Test whether a tool call would pass the warrant's policy:
1. Enter a **tool name** (e.g., `read_file`)
2. Provide **arguments** as JSON (e.g., `{"path": "docs/readme.md"}`)
3. Click **Check Authorization** to see pass/fail with detailed reasons

This runs in **dry run mode** - it checks the policy (tools, constraints, TTL) but skips PoP signature verification since we don't have the holder's private key.

### 📋 Sample Warrants
Pre-loaded samples demonstrate common scenarios:
- ✅ **Valid Read** - Path matches `docs/*` constraint
- ✅ **Nested Path** - Deep paths like `docs/api/guide.md`
- ⏰ **Expiring (10s)** - Watch a warrant expire in real-time!
- ❌ **Wrong Path** - `/etc/passwd` blocked by constraint
- ❌ **Wrong Tool** - `delete_file` not in authorized tools

### 🏗️ Builder Mode
Construct new warrants visually:
- Add tools with constraints
- Set TTL and delegation depth
- Generate the warrant structure

### 📊 Diff Mode
Compare two warrants side-by-side:
- See what changed between versions
- Highlight added/removed tools
- Track constraint narrowing

### 📚 Delegation Mode
Understand how multi-hop delegation works:

1. **Paste warrants** in order (root → delegate → delegate...)
2. Each warrant is decoded and validated
3. **Visual chain** shows holder → issuer connections
4. **Test authorization** against the full chain

**What it verifies:**
- Holder of warrant N = Issuer of warrant N+1
- Tools only shrink (monotonic attenuation)
- Constraints only tighten
- TTL only decreases
- Signature chain is valid

This mode is primarily **educational**—it helps you understand how Tenuo's delegation model works and debug complex multi-agent scenarios.

## Quick Start

```bash
# Install dependencies
npm install

# Start dev server
npm run dev

# Start with fresh WASM rebuild
npm run dev:fresh
```

## npm Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start Vite dev server |
| `npm run dev:fresh` | Rebuild WASM, then start dev server |
| `npm run wasm` | Rebuild WASM bindings only |
| `npm run build` | Production build (auto-rebuilds WASM) |
| `npm run test` | Run unit tests (Vitest) |
| `npm run test:e2e` | Run E2E tests (Playwright) |

## How It Works

```
┌────────────────────────────────────────────────────────────────┐
│  Browser                                                       │
│  ┌──────────────────┐    ┌─────────────────────────────────┐  │
│  │   React UI       │───▶│   tenuo-wasm (WebAssembly)      │  │
│  │   - Decoder      │    │   - decode_warrant()            │  │
│  │   - Simulator    │    │   - check_access()              │  │
│  │   - Builder      │    │   - create_sample_warrant()     │  │
│  └──────────────────┘    └─────────────────────────────────┘  │
│           │                           │                        │
│           ▼                           ▼                        │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  LocalStorage: history, presets                          │ │
│  └──────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────┘
```

All operations run **entirely in the browser**:
- Warrants are decoded by WASM (same Rust code as the server SDK)
- No network requests—your data never leaves the page
- History is stored in `localStorage` for convenience

## WASM Functions

The explorer calls these functions from `tenuo-wasm`:

| Function | Purpose |
|----------|---------|
| `decode_warrant(b64)` | Parse warrant, return JSON structure |
| `check_access(warrant, tool, args, root, dry_run)` | Simulate authorization (policy check) |
| `check_chain_access(warrants[], tool, args, root)` | Verify delegation chain authorization |
| `create_sample_warrant(tool, field, pattern, ttl)` | Generate fresh test warrants |

### About Proof-of-Possession (PoP)

In production, Tenuo requires **Proof-of-Possession** - the holder must sign each request with their private key. This prevents stolen warrants from being used (the attacker has the token but not the key).

The explorer runs in **dry run mode** (policy check only) because:
- We don't have the holder's private key (only they do)
- A random keypair won't match the warrant's `authorized_holder`
- The policy check still validates: tools, constraints, TTL, issuer chain

## Rebuilding WASM

When you change `tenuo-core`, rebuild the WASM:

```bash
# Option 1: Use npm script
npm run wasm

# Option 2: Manual
cd ../tenuo-wasm
wasm-pack build --release --target web --out-dir pkg
cp pkg/* ../tenuo-explorer/src/wasm/
```

## Tech Stack

- ⚛️ React 18
- 🦀 Rust → WASM (via wasm-pack)
- ⚡ Vite
- 🎨 CSS (custom dark theme)
- 📝 TypeScript
- 🧪 Vitest + Playwright

## Debugging

Open browser DevTools console to see:
```
[Tenuo Explorer] Initializing WASM...
[Tenuo Explorer] WASM loaded successfully ✓
[Tenuo Explorer] Generated 7 fresh sample warrants
[Tenuo Explorer] Decoding warrant...
[Tenuo Explorer] Decode successful: {...}
```

## Known Limitations

This is a **debugging tool** for inspecting warrants, not part of any trust chain.

| Limitation | Notes |
|------------|-------|
| **Policy check only** | Checks tools, constraints, TTL - not PoP (we don't have holder's key) |
| **No persistence** | Use "Share URL" to bookmark a warrant for later |
| **Samples expire on refresh** | Fresh samples are generated on each page load |
| **Builder = preview only** | Generates structure preview; use SDK to actually create |

### Security Notes

- ✅ **No data leaves the browser** - All decoding happens in WASM
- ✅ **No private keys in browser** - Explorer never has signing capability
- ✅ **Warrants are safe to share** - PoP means warrants are useless without the holder's private key
- ℹ️ **Share URLs expose warrant structure** - Tool names and constraints are visible (by design—it's a debugging tool)

## License

Apache 2.0 - See [LICENSE](../LICENSE)
