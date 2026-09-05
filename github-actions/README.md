# Tenuo for GitHub Actions

Checks warrants and writes file receipts. The holder process keeps the run key
behind a Unix socket; `mcp_config` launches a stdio shim that never sees it.

The gateway is the GitHub credential. Cloud (or a self-hosted exchange) issues
warrants. The warrant is the program; the gateway interprets it, then mints an
installation token and calls `api.github.com`. Packs are HTTP recipes, not a
second ACL. Do not point `TENUO_GATEWAY_URL` at Tenuo Cloud.

Cluster install is `charts/tenuo-github-actions` (`secret` profile, two
identities). See that chart's README. `kms` is not in this image yet.

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
PYTHONPATH=github-actions python -m tenuo_gha box \
    --config github-actions/examples/gateway-secret.yaml \
    --mount github-actions/examples/secrets
# from the monorepo root; installs tenuo from PyPI unless docker/wheels/ has a wheel
docker compose -f github-actions/examples/compose.yaml up --build
# compose is healthy only after /ready can sign
PYTHONPATH=github-actions python -m tenuo_gha doctor \
    --gateway-url http://127.0.0.1:8000 --gateway-only
```

Then set org vars `TENUO_GATEWAY_URL`, `TENUO_EXCHANGE_URL`,
`TENUO_EXCHANGE_AUDIENCE`, and `TENUO_TRUSTED_ROOTS`, pin a commit of
`tenuo-ai/tenuo/github-actions`, and run doctor against Cloud. `@main` is not
an allowlist.

Customer-gateway configuration is four fields:

| Field | Meaning |
|---|---|
| `gateway_url` | Customer gateway. Never Cloud. |
| `exchange_url` | Cloud or self-hosted `POST /v1/exchange`. |
| `audience` | Self-hosted `exchange.audience`, or Cloud `tenuo:org/<tenant>`. |
| `trusted_roots` | Deploy-time roots. The action checks advertised keys; the gateway `trust.root_public_keys` is the Authorizer anchor. |

```yaml
- uses: tenuo-ai/tenuo/github-actions@<sha>
  with:
    gateway_url: ${{ vars.TENUO_GATEWAY_URL }}
    exchange_url: ${{ vars.TENUO_EXCHANGE_URL }}
    audience: ${{ vars.TENUO_EXCHANGE_AUDIENCE }}
    trusted_roots: ${{ vars.TENUO_TRUSTED_ROOTS }}
```

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

# Live Cloud exchange (GitHub Actions OIDC + customer gateway App)
TENUO_LIVE_CLOUD=1 \
TENUO_EXCHANGE_URL=https://api-staging.tenuo.ai \
TENUO_EXCHANGE_AUDIENCE=tenuo:org/<tenant> \
TENUO_TRUSTED_ROOTS=<hex> \
TENUO_GITHUB_APP_ID=<app id> \
TENUO_GITHUB_APP_KEY_FILE=/path/to/app.pem \
python -m pytest -q tests/test_live_cloud.py
```

The JavaScript action installs third-party deps from `requirements.lock` with `--require-hashes`, then installs the Ubuntu/manylinux `tenuo` wheel from `vendor/`. `package_runtime.py` copies that wheel into the assembled action; a CI-built wheel that is not packaged is not enough. v1 supports Ubuntu runners. The holder socket path includes `$GITHUB_RUN_ID`. The post step stops the holder and removes temporary socket and mcp_config files.
