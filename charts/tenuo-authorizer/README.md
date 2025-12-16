# Tenuo Authorizer Helm Chart

Deploy the Tenuo authorizer as a high-availability service in Kubernetes.

## TL;DR

```bash
helm install tenuo-authorizer ./charts/tenuo-authorizer \
  --set config.trustedRoots[0]="f32e74b5b8569dc288db0109b7ec0d8eb3b4e5be7b07c647171d53fd31e7391f"
```

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+

## Installing the Chart

```bash
# Install with default values
helm install tenuo-authorizer ./charts/tenuo-authorizer

# Install with custom values
helm install tenuo-authorizer ./charts/tenuo-authorizer -f my-values.yaml

# Install in a specific namespace
helm install tenuo-authorizer ./charts/tenuo-authorizer --namespace tenuo-system --create-namespace
```

## Uninstalling the Chart

```bash
helm uninstall tenuo-authorizer
```

## Configuration

### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Image repository | `tenuo/authorizer` |
| `image.tag` | Image tag | `""` (uses chart appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |

### Tenuo Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.warrantHeader` | HTTP header for warrant | `X-Tenuo-Warrant` |
| `config.popHeader` | HTTP header for PoP signature | `X-Tenuo-PoP` |
| `config.clockToleranceSecs` | Clock tolerance for expiration | `30` |
| `config.trustedRoots` | List of trusted issuer public keys (hex) | `[]` |
| `config.debugMode` | Enable debug mode (adds deny reason header) | `false` |

### Gateway Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `gateway.tools` | Tool definitions with extraction rules | `{}` |
| `gateway.routes` | Route matching configuration | `[]` |

### Service Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `9090` |
| `service.annotations` | Service annotations | `{}` |

### Resource Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `200m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `50m` |
| `resources.requests.memory` | Memory request | `64Mi` |

### High Availability

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable HPA | `false` |
| `autoscaling.minReplicas` | Minimum replicas | `2` |
| `autoscaling.maxReplicas` | Maximum replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU % | `80` |
| `podDisruptionBudget.enabled` | Enable PDB | `true` |
| `podDisruptionBudget.minAvailable` | Minimum available pods | `1` |

## Examples

### Basic Deployment with Trusted Keys

```yaml
# values.yaml
config:
  trustedRoots:
    - "f32e74b5b8569dc288db0109b7ec0d8eb3b4e5be7b07c647171d53fd31e7391f"
    - "a1b2c3d4e5f6789..."
```

### With Gateway Configuration

```yaml
# values.yaml
config:
  trustedRoots:
    - "f32e74b5..."

gateway:
  tools:
    manage_infrastructure:
      description: "Kubernetes cluster management"
      constraints:
        cluster:
          from: path
          path: "cluster"
          required: true
        action:
          from: path
          path: "action"
          required: true
  
  routes:
    - pattern: "/api/v1/clusters/{cluster}/{action}"
      method: ["POST", "PUT"]
      tool: "manage_infrastructure"
```

### With Autoscaling

```yaml
# values.yaml
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70

podDisruptionBudget:
  enabled: true
  minAvailable: 2
```

### Production Configuration

```yaml
# production-values.yaml
replicaCount: 3

config:
  trustedRoots:
    - "production-key-1"
    - "production-key-2"
  clockToleranceSecs: 10
  debugMode: false

resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 50
  targetCPUUtilizationPercentage: 75

podDisruptionBudget:
  enabled: true
  minAvailable: 2

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchExpressions:
              - key: app.kubernetes.io/name
                operator: In
                values:
                  - tenuo-authorizer
          topologyKey: kubernetes.io/hostname
```

## Integration with Istio

To use with Istio's external authorization:

1. Install the chart:
```bash
helm install tenuo-authorizer ./charts/tenuo-authorizer \
  --namespace tenuo-system \
  --create-namespace \
  --set config.trustedRoots[0]="YOUR_KEY_HERE"
```

2. Configure Istio ExtensionProvider (see [Istio Quickstart](../../docs/quickstart/istio/))

3. Apply AuthorizationPolicy to your services

## Upgrading

```bash
# Upgrade with new values
helm upgrade tenuo-authorizer ./charts/tenuo-authorizer -f new-values.yaml

# Upgrade to a new chart version
helm upgrade tenuo-authorizer ./charts/tenuo-authorizer --version 0.2.0
```

## Troubleshooting

### Check pod status
```bash
kubectl get pods -l app.kubernetes.io/name=tenuo-authorizer
```

### View logs
```bash
kubectl logs -l app.kubernetes.io/name=tenuo-authorizer --tail=50
```

### Test the service
```bash
kubectl port-forward svc/tenuo-authorizer 9090:9090
grpcurl -plaintext localhost:9090 list
```

### Verify configuration
```bash
kubectl get configmap tenuo-authorizer-config -o yaml
```

## Security Considerations

- **Never enable `debugMode` in production** - it exposes denial reasons in headers
- **Use strong trusted root keys** - these are the foundation of your security
- **Trusted roots are configured via ConfigMap** - the chart uses the gateway config file as the single source of truth for trusted issuers, avoiding environment variable/config file conflicts
- **Enable PodDisruptionBudget** - ensures availability during cluster maintenance
- **Set resource limits** - prevents resource exhaustion attacks
- **Use read-only root filesystem** - reduces attack surface
- **Pod anti-affinity is enabled by default** - spreads replicas across nodes for better HA

## See Also

- [Kubernetes Integration Guide](../../docs/kubernetes.md)
- [Istio Quickstart](../../docs/quickstart/istio/)
- [Gateway Configuration Reference](../../docs/gateway-config.md)
