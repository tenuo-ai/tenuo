# Gateway Configuration Starter Templates

This directory contains starter templates for common gateway configurations. Use these as a foundation for your own gateway configs.

## Available Templates

### [file-operations.yaml](./file-operations.yaml)
For file read/write operations with path-based constraints.

**Use cases:**
- File system access control
- Document management systems
- Configuration file editing

### [database-query.yaml](./database-query.yaml)
For database operations with table and operation constraints.

**Use cases:**
- SQL database access
- NoSQL operations
- Data warehouse queries

### [kubernetes-ops.yaml](./kubernetes-ops.yaml)
For Kubernetes cluster management operations.

**Use cases:**
- Pod scaling
- Deployment updates
- Resource management

### [http-request.yaml](./http-request.yaml)
For HTTP API requests with path and method constraints.

**Use cases:**
- REST API gateways
- Microservice authorization
- External API access control

## Usage

1. **Copy a template** that matches your use case:
   ```bash
   cp templates/gateway/kubernetes-ops.yaml my-gateway.yaml
   ```

2. **Customize** the configuration:
   - Update `trusted_roots` with your control plane public key
   - Modify tools and constraints for your specific needs
   - Adjust routes to match your API patterns

3. **Validate** your configuration:
   ```bash
   tenuo-authorizer validate --config my-gateway.yaml
   ```

4. **Test** with the explain command:
   ```bash
   tenuo-authorizer explain --config my-gateway.yaml \
     --method POST \
     --path "/api/v1/clusters/staging/scale" \
     --body '{"replicas": 3}'
   ```

## Customization Tips

### Adding Constraints
Constraints can extract values from:
- **path**: URL path parameters (`/api/{cluster}/{action}`)
- **query**: Query string (`?namespace=default`)
- **header**: HTTP headers (`X-Tenant-Id`)
- **body**: JSON body with dot notation (`spec.replicas`)

### Constraint Types
- `string`: Text values
- `integer`: Whole numbers (i64)
- `float`: Decimal numbers (f64)
- `boolean`: true/false
- `list`: Arrays (use wildcards: `items.*.id`)

### Required vs Optional
- Set `required: true` for mandatory fields
- Use `default: value` for optional fields with fallback values

## See Also

- [Gateway Configuration Reference](../../docs/gateway-config.md)
- [Kubernetes Integration Guide](../../docs/kubernetes-integration.md)
- [Example Configurations](../../examples/)
