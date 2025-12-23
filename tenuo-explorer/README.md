# Tenuo Explorer

🔐 **WASM-powered warrant decoder & authorization playground**

A browser-based tool for inspecting Tenuo warrants, visualizing delegation chains, and simulating authorization checks—all running locally in WebAssembly.

## Features

- **Warrant Decoder** - Paste a base64 warrant and instantly inspect its contents
- **Chain Visualizer** - See the delegation path from issuer to holder
- **Expiration Timeline** - Real-time countdown showing warrant validity
- **Authorization Simulator** - Test tool calls against warrant constraints
- **Dry Run Mode** - Check policies without requiring PoP signatures
- **Shareable URLs** - Generate links to share warrant configurations

## Development

```bash
# Install dependencies
npm install

# Start dev server
npm run dev

# Build for production
npm run build
```

## WASM Bindings

The explorer uses `tenuo-wasm` for core warrant operations:

- `decode_warrant(base64)` - Parse and decode a warrant
- `check_access(warrant, tool, args, root_key, dry_run)` - Simulate authorization
- `check_chain_access(warrants[], tool, args, root_key)` - Check warrant chains

## Building WASM

```bash
cd ../tenuo-wasm
wasm-pack build --target web --out-dir ../tenuo-explorer/src/wasm
```

## Tech Stack

- ⚛️ React 19
- 🦀 Rust → WASM (via wasm-pack)
- ⚡ Vite
- 🎨 Tailwind CSS
- 📝 TypeScript

## License

Apache 2.0 - See [LICENSE](../LICENSE)
