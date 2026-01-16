# Development Guide for Claude

## Quick Commands

```bash
# Build
go build ./...

# Test
go test ./...

# Deploy to local Kind clusters
make deploy

# Check logs
kubectl logs -n kube-federated-auth deploy/kube-federated-auth --context kind-cluster-a
```

## Local Development Setup

The project uses two Kind clusters for testing:
- **cluster-a**: Runs kube-federated-auth server
- **cluster-b**: Remote cluster whose tokens are validated

```bash
# Setup Kind clusters (if not exists)
scripts/setup-kind-clusters.sh

# Deploy everything
make deploy
```

## Testing the API

Use the test-client pod deployed in cluster-a:

```bash
# Health check
kubectl exec -n kube-federated-auth deploy/test-client --context kind-cluster-a -- \
  curl -s http://kube-federated-auth:8080/health

# List clusters
kubectl exec -n kube-federated-auth deploy/test-client --context kind-cluster-a -- \
  curl -s http://kube-federated-auth:8080/clusters | jq .

# Validate a token from cluster-b using TokenReview API
TOKEN=$(kubectl create token kube-federated-auth-reader --context kind-cluster-b -n kube-federated-auth --duration=1h)
kubectl exec -n kube-federated-auth deploy/test-client --context kind-cluster-a -- \
  curl -s -X POST http://api.cluster-b.kube-fed:8080/apis/authentication.k8s.io/v1/tokenreviews \
  -H "Content-Type: application/json" \
  -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"$TOKEN\"}}" | jq .
```

## Project Structure

```
cmd/server/main.go          # Entry point
internal/
  config/config.go          # Configuration parsing and defaults
  credentials/
    renewer.go              # Token renewal logic with renew_before threshold
    store.go                # Credential storage (in-memory + K8s Secret)
  handler/
    tokenreview.go          # POST /apis/authentication.k8s.io/v1/tokenreviews endpoint
    clusters.go             # GET /clusters endpoint
  oidc/verifier.go          # OIDC/JWKS token verification
  server/server.go          # HTTP server setup
k8s/
  cluster-a/                # Helm chart for main cluster (runs server)
  cluster-b/                # Helm chart for remote cluster (ServiceAccount only)
config/clusters.example.yaml # Example configuration
docs/
  DESIGN_V2.md              # V2 architecture design document
```

## Git Commit Convention

```
<type>: <short description>

[optional body]
```

Types: feat, fix, refactor, chore, docs, build, test

No "Generated with Claude" footer or Co-Authored-By lines.
