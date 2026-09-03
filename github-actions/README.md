# Tenuo for GitHub Actions

Checks warrants and writes file receipts. The holder process keeps the run key
behind a Unix socket; `mcp_config` launches a stdio shim that never sees it.

```bash
PYTHONPATH=github-actions python -m tenuo_gha.check

TENUO_ALLOW_INSECURE_MEMORY_KEYS=1 \
TENUO_ROOT_PUBLIC_KEY=<hex> \
python -m tenuo_gha --config github-actions/examples/gateway.yaml

python -m tenuo_gha hold --socket /tmp/tenuo.sock
python -m tenuo_gha shim --socket /tmp/tenuo.sock --gateway-url http://127.0.0.1:8000
```
