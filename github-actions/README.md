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

# Job path: OIDC → exchange → holder → mcp_config
python -m tenuo_gha action --gateway-url URL --exchange-url URL --audience tenuo:org/acme

# Live GitHub (creates a disposable issue, comments, closes it)
TENUO_LIVE_GITHUB=1 GH_TOKEN="$(gh auth token)" python -m pytest -q tests/test_live_github.py
```

The JavaScript action installs third-party deps from `requirements.lock` with `--require-hashes`. It does not `pip install` this package from PyPI. The holder socket path includes `$GITHUB_RUN_ID`. The post step stops the holder and removes temporary socket and mcp_config files.
