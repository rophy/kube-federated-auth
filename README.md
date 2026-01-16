# kube-federated-auth

Federated ServiceAccount authentication across Kubernetes clusters.

Validate ServiceAccount tokens from multiple Kubernetes clusters using their OIDC endpoints. Enables cross-cluster workload authentication without service meshes or additional identity infrastructure.

## How It Works

```mermaid
flowchart LR
    subgraph cluster-a["cluster-a (service)"]
        svc[my-svc]
        kfa[kube-federated-auth]
        svc -->|1. TokenReview| kfa
    end

    subgraph cluster-b["cluster-b (client)"]
        client[client]
        oidc[OIDC endpoint]
    end

    client -->|2. send SA token| svc
    kfa -->|3. fetch JWKS| oidc
```

1. Client workload sends its ServiceAccount token to your service
2. Your service calls kube-federated-auth using standard Kubernetes TokenReview API
3. kube-federated-auth validates the JWT against the cluster's OIDC/JWKS
4. Your service authorizes based on returned user info

## Quick Start

```bash
# Run locally
go run ./cmd/server --config=config/clusters.yaml

# Or with Docker
docker run -v $(pwd)/config:/etc/kube-federated-auth ghcr.io/rophy/kube-federated-auth
```

## Configuration

```yaml
# config/clusters.yaml
renewal:
  interval: "1h"          # How often to check for renewal
  token_duration: "168h"  # Requested token TTL (7 days)
  renew_before: "48h"     # Renew when <48h remaining

clusters:
  # Local cluster (uses in-cluster OIDC)
  local:
    issuer: "https://kubernetes.default.svc.cluster.local"

  # EKS cluster (public OIDC endpoint)
  eks-prod:
    issuer: "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE"

  # Remote cluster with private OIDC (requires credentials)
  cluster-b:
    issuer: "https://kubernetes.default.svc.cluster.local"
    api_server: "https://192.168.1.100:6443"
    ca_cert: "/etc/kube-federated-auth/certs/cluster-b-ca.crt"
    token_path: "/etc/kube-federated-auth/certs/cluster-b-token"
```

## API

### POST /apis/authentication.k8s.io/v1/tokenreviews

Standard Kubernetes TokenReview API. The target cluster is determined by the hostname.

**Hostname-based routing:**

| Hostname | Cluster |
|----------|---------|
| `api.kube-fed.svc.cluster.local` | `local` |
| `api.{cluster}.kube-fed.svc.cluster.local` | `{cluster}` |

**Request:**

```bash
curl -X POST http://api.cluster-b.kube-fed.svc.cluster.local:8080/apis/authentication.k8s.io/v1/tokenreviews \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "authentication.k8s.io/v1",
    "kind": "TokenReview",
    "spec": {
      "token": "<sa-token>"
    }
  }'
```

**Success response:**

```json
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenReview",
  "status": {
    "authenticated": true,
    "user": {
      "username": "system:serviceaccount:default:my-app",
      "uid": "abc-123",
      "groups": [
        "system:serviceaccounts",
        "system:serviceaccounts:default"
      ]
    },
    "audiences": ["api"]
  }
}
```

**Error response:**

```json
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenReview",
  "status": {
    "authenticated": false,
    "error": "token has expired"
  }
}
```

### GET /clusters

List configured clusters and their status.

```json
{
  "clusters": [
    {
      "name": "local",
      "issuer": "https://kubernetes.default.svc.cluster.local",
      "token_status": {
        "status": "valid"
      }
    },
    {
      "name": "cluster-b",
      "issuer": "https://kubernetes.default.svc.cluster.local",
      "api_server": "https://192.168.128.3:6443",
      "token_status": {
        "expires_at": "2025-12-21T13:26:40Z",
        "expires_in": "167h50m4s",
        "status": "valid"
      }
    }
  ]
}
```

### GET /health

```json
{"status":"ok"}
```

## Kubernetes Services

Create a service per cluster to enable hostname-based routing:

```yaml
# Service for local cluster
apiVersion: v1
kind: Service
metadata:
  name: api.kube-fed
  namespace: kube-federated-auth
spec:
  selector:
    app: kube-federated-auth
  ports:
    - port: 443
      targetPort: 8080
---
# Service for remote cluster
apiVersion: v1
kind: Service
metadata:
  name: api.cluster-b.kube-fed
  namespace: kube-federated-auth
spec:
  selector:
    app: kube-federated-auth
  ports:
    - port: 443
      targetPort: 8080
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIG_PATH` | `config/clusters.yaml` | Path to config file |
| `PORT` | `8080` | Server port |
| `NAMESPACE` | `kube-federated-auth` | Namespace for credential secret |
| `SECRET_NAME` | `kube-federated-auth` | Secret name for credentials |

## License

MIT
