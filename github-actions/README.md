# Tenuo for GitHub Actions

Verify-only gateway (M2). It checks warrants, emits file receipts, and never
calls GitHub. Tripwires (`workflow_dispatch`, `install_package`, …) are
registered so the containment check can call them and watch them fail.

```bash
# Containment fixtures (must deny the attack shapes):
PYTHONPATH=github-actions python -m tenuo_gha.check

# HTTP entrypoint (verify-only; memory keys are test-only):
TENUO_ALLOW_INSECURE_MEMORY_KEYS=1 \
TENUO_ROOT_PUBLIC_KEY=<hex> \
python -m tenuo_gha --config github-actions/examples/gateway.yaml
```

Production custody (KMS, `/v1/exchange`, App tokens) is M3+.
