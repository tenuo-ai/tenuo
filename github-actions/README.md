# Tenuo for GitHub Actions

Checks warrants and writes file receipts. Tool handlers do not call GitHub.

```bash
PYTHONPATH=github-actions python -m tenuo_gha.check

TENUO_ALLOW_INSECURE_MEMORY_KEYS=1 \
TENUO_ROOT_PUBLIC_KEY=<hex> \
python -m tenuo_gha --config github-actions/examples/gateway.yaml
```
