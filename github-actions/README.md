# Tenuo for GitHub Actions

Checks warrants and writes file receipts. The holder process keeps the run key
behind a Unix socket; `mcp_config` launches a stdio shim that never sees it.

The gateway is the GitHub credential. Cloud (or a self-hosted exchange) issues
warrants. Do not point `TENUO_GATEWAY_URL` at Tenuo Cloud.

## Concierge box (`secret` profile)

Create a GitHub App in Settings (issues read/write). Download the PEM once, copy
it to a Secret mount as `app.pem`, and delete the download. Generate a receipt
key into the same mount. The process loads those files at start; a PEM in the
environment or next to the config YAML is a startup error.

```bash
PYTHONPATH=github-actions python -m tenuo_gha init-secrets \
    --mount github-actions/examples/secrets \
    --app-pem /path/to/app.pem
export TENUO_ROOT_PUBLIC_KEY=<hex of the Cloud or exchange root>
export TENUO_GITHUB_APP_ID=<app id>
export TENUO_REPOSITORY=acme/widgets
# from the monorepo root, after a tenuo wheel exists
docker compose -f github-actions/examples/compose.yaml up --build
```

Then set org vars `TENUO_GATEWAY_URL`, `TENUO_EXCHANGE_URL`, and
`TENUO_EXCHANGE_AUDIENCE`, pin the action SHA, and run doctor.

```bash
PYTHONPATH=github-actions python -m tenuo_gha doctor \
    --gateway-url URL --exchange-url URL --audience tenuo:org/acme
```

Live App-signed comment (PEM file, not `GH_TOKEN`):

```bash
TENUO_LIVE_GITHUB=1 \
TENUO_GITHUB_APP_ID=<app id> \
TENUO_GITHUB_APP_KEY_FILE=/path/to/app.pem \
python -m pytest -q tests/test_live_github.py -k live_app
```

Copy `.github/workflows/agent.yml` into the org and add the agent step in that
same job (`mcp_config` is a local path). Each job writes a "This run may"
summary from the issued warrant.

```bash
PYTHONPATH=github-actions python -m tenuo_gha check

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

The JavaScript action installs third-party deps from `requirements.lock` with `--require-hashes`, then installs the Ubuntu/manylinux `tenuo` wheel from `vendor/`. `package_runtime.py` copies that wheel into the assembled action; a CI-built wheel that is not packaged is not enough. v1 supports Ubuntu runners. The holder socket path includes `$GITHUB_RUN_ID`. The post step stops the holder and removes temporary socket and mcp_config files.
