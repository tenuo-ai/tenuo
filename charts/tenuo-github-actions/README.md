# Tenuo for GitHub Actions

Two Deployments, two ServiceAccounts, `secret` profile. There is no values knob that merges the identities.

`signing.profile=kms` is not implemented in this image. The chart fails closed if you select it.

## Install

Create two Secrets. The exchange Secret holds only the issuer key. The gateway Secret holds the receipt key and the GitHub App PEM.

```bash
kubectl create secret generic tenuo-exchange-keys \
  --from-file=issuer.pem=/path/to/issuer.pem

kubectl create secret generic tenuo-gateway-keys \
  --from-file=receipt.pem=/path/to/receipt.pem \
  --from-file=app.pem=/path/to/app.pem

helm install tenuo ./charts/tenuo-github-actions \
  --set trust.rootPublicKeys[0]="$(xxd -p -c 256 /path/to/issuer.pub)" \
  --set exchange.audience=tenuo:org/acme \
  --set exchange.secrets.existingSecret=tenuo-exchange-keys \
  --set gateway.secrets.existingSecret=tenuo-gateway-keys \
  --set github.appId=123456
```

Prefer pinning `image.digest` once the image is published. Until then, build the concierge image from `github-actions/Dockerfile` and set `image.registry`, `image.repository`, and `image.tag`.

## Required values

| Value | Meaning |
|---|---|
| `trust.rootPublicKeys` | Hex public keys the gateway verifies against |
| `exchange.audience` | OIDC audience the job must request |
| `exchange.secrets.existingSecret` | Secret with `issuer.pem` |
| `gateway.secrets.existingSecret` | Secret with `receipt.pem` and `app.pem` |
| `github.appId` | GitHub App id |

The two `existingSecret` names must differ. A shared Secret is a chart error.

## After install

Point the action at the two Services. Do not point `TENUO_GATEWAY_URL` at Tenuo Cloud.
Cloud customers set `TENUO_EXCHANGE_URL` to the Cloud API and keep the gateway Service.

```text
TENUO_GATEWAY_URL=http://<release>-tenuo-github-actions-gateway.<ns>.svc:8000
TENUO_EXCHANGE_URL=http://<release>-tenuo-github-actions-exchange.<ns>.svc:8000
TENUO_EXCHANGE_AUDIENCE=tenuo:org/acme
TENUO_TRUSTED_ROOTS=<hex of trust.rootPublicKeys>
```

Action pin until v1: `uses: tenuo-ai/tenuo/github-actions@<sha>` with
`gateway_url`, `exchange_url`, `audience`, and `trusted_roots`.
