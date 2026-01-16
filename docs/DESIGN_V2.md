# kube-federated-auth V2 Design

## Overview

V2 provides a **standard Kubernetes TokenReview API** that automatically detects the source cluster and validates tokens with real-time revocation support. Service providers need **zero code changes** - just point to kube-federated-auth instead of the local API server.

## Goals

1. **Standard API**: Fully compliant Kubernetes TokenReview API
2. **Zero Integration Effort**: Service providers use identical code for local and cross-cluster
3. **Automatic Cluster Detection**: No cluster specification needed from callers
4. **Real-time Revocation**: Tokens bound to deleted objects are immediately rejected
5. **Security**: No token leakage during cluster detection

## Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Service Provider                                                            │
│                                                                             │
│   // Same code for local or cross-cluster - just different endpoint         │
│   POST https://kube-fed.svc/apis/authentication.k8s.io/v1/tokenreviews      │
│   Body: {"spec": {"token": "<client-token>"}}                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ kube-federated-auth                                                         │
│                                                                             │
│   Step 1: JWKS Cluster Detection (local, no token leakage)                  │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ for each configured cluster:                                        │   │
│   │   verify JWT signature using cached JWKS                            │   │
│   │   if signature valid → found source cluster                         │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│   Step 2: TokenReview Forwarding (authoritative validation)                 │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ Forward TokenReview request to detected cluster's API server        │   │
│   │ → Real-time revocation check                                        │   │
│   │ → Bound object validation                                           │   │
│   │ → Authoritative user info                                           │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                      │
│                                      ▼                                      │
│   Return standard TokenReview response                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Why Hybrid JWKS + TokenReview?

| Approach | Token Leakage | Revocation | Efficiency |
|----------|---------------|------------|------------|
| JWKS only | None | No (until expiry) | Fast |
| TokenReview to all clusters | Yes (tokens sent everywhere) | Yes | Slow, insecure |
| **Hybrid (JWKS detect + TokenReview forward)** | **None** | **Yes** | **Optimal** |

**Hybrid approach:**
1. **JWKS detection** - Local cryptographic verification, tokens never leave kube-federated-auth
2. **TokenReview forwarding** - One call to the correct cluster for authoritative validation

## API Specification

### Endpoint

```
POST /apis/authentication.k8s.io/v1/tokenreviews
```

**Single endpoint** - no cluster-specific hostnames or routing needed.

### Request

Standard Kubernetes TokenReview:

```json
{
  "apiVersion": "authentication.k8s.io/v1",
  "kind": "TokenReview",
  "spec": {
    "token": "eyJhbGciOiJSUzI1NiIs...",
    "audiences": ["my-service"]
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `spec.token` | string | Yes | The ServiceAccount JWT token to validate |
| `spec.audiences` | []string | No | Expected audiences for the token |

### Response

Standard Kubernetes TokenReview:

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
      ],
      "extra": {
        "authentication.kubernetes.io/pod-name": ["my-pod"],
        "authentication.kubernetes.io/pod-uid": ["pod-uid-123"]
      }
    },
    "audiences": ["my-service"]
  }
}
```

### Error Response

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

## Internal Implementation

### Step 1: JWKS Cluster Detection

```go
func (h *Handler) detectCluster(token string) (string, error) {
    // Iterate all configured clusters
    for clusterName := range h.config.Clusters {
        // Try to verify signature using cluster's cached JWKS
        _, err := h.verifier.Verify(ctx, clusterName, token)
        if err == nil {
            return clusterName, nil
        }
        // Signature mismatch - try next cluster
    }
    return "", errors.New("token not valid for any configured cluster")
}
```

**Key properties:**
- Local cryptographic verification only
- Token never sent over network during detection
- Each cluster has unique signing keys - only one will match

### Step 2: TokenReview Forwarding

```go
func (h *Handler) forwardTokenReview(ctx context.Context, cluster string, tr *authv1.TokenReview) (*authv1.TokenReview, error) {
    // Get credentials for the target cluster
    creds := h.credStore.Get(cluster)

    // Create client for remote cluster's API server
    client := kubernetes.NewForConfig(&rest.Config{
        Host:            h.config.Clusters[cluster].APIServer,
        BearerToken:     creds.Token,
        TLSClientConfig: rest.TLSClientConfig{CAData: creds.CACert},
    })

    // Forward TokenReview request
    return client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
}
```

**Why forward instead of using JWKS claims?**
- Real-time revocation: If the Pod or ServiceAccount is deleted, the token is immediately invalid
- Authoritative response: User info comes directly from the cluster
- Bound object validation: Kubernetes checks if bound objects still exist

## Service Provider Integration

### Before (Local Only)

```go
client := kubernetes.NewForConfig(rest.InClusterConfig())
result, err := client.AuthenticationV1().TokenReviews().Create(ctx, &authv1.TokenReview{
    Spec: authv1.TokenReviewSpec{Token: clientToken},
}, metav1.CreateOptions{})
```

### After (Cross-Cluster via kube-federated-auth)

```go
// Option 1: Use kube-federated-auth service
config := &rest.Config{Host: "https://kube-fed.svc"}
client := kubernetes.NewForConfig(config)
result, err := client.AuthenticationV1().TokenReviews().Create(ctx, &authv1.TokenReview{
    Spec: authv1.TokenReviewSpec{Token: clientToken},
}, metav1.CreateOptions{})
```

Or simply:

```go
// Option 2: Direct HTTP call
resp, err := http.Post(
    "http://kube-fed.svc/apis/authentication.k8s.io/v1/tokenreviews",
    "application/json",
    bytes.NewReader(tokenReviewJSON),
)
```

**The code is identical** - only the endpoint URL changes.

## Configuration

### Cluster Configuration

```yaml
clusters:
  # Local cluster
  local:
    issuer: "https://kubernetes.default.svc.cluster.local"

  # Remote clusters (JWKS fetched via api_server, TokenReview forwarded here)
  cluster-b:
    issuer: "https://kubernetes.default.svc.cluster.local"
    api_server: "https://cluster-b.example.com:6443"
    ca_cert: "/etc/kube-fed/clusters/cluster-b/ca.crt"
    token_path: "/etc/kube-fed/clusters/cluster-b/token"

  cluster-c:
    issuer: "https://kubernetes.default.svc.cluster.local"
    api_server: "https://cluster-c.example.com:6443"
    ca_cert: "/etc/kube-fed/clusters/cluster-c/ca.crt"
    token_path: "/etc/kube-fed/clusters/cluster-c/token"

renewal:
  interval: 1h
  token_duration: 168h
  renew_before: 48h
```

### Kubernetes Service

Single service - no per-cluster services needed:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: kube-fed
  namespace: kube-federated-auth
spec:
  selector:
    app: kube-federated-auth
  ports:
    - port: 443
      targetPort: 8080
```

## V1 vs V2 Comparison

| Aspect | V1 | V2 |
|--------|----|----|
| API | Custom `/validate` | Standard TokenReview |
| Cluster routing | Explicit in request body | Auto-detected via JWKS |
| Revocation | No (JWKS only) | Yes (TokenReview forwarding) |
| Service provider changes | Custom API client | **None** - just change endpoint |
| Token leakage | N/A | None (JWKS is local) |
| K8s services needed | One per cluster | **One total** |

## Security Considerations

### Token Leakage Prevention

During cluster detection, tokens are **never sent to any cluster**. JWKS verification is purely local:
1. Decode JWT header to get key ID
2. Look up public key from cached JWKS
3. Verify signature locally

Only after the source cluster is cryptographically identified is the token forwarded to that specific cluster's TokenReview API.

### Authentication of Callers

The TokenReview endpoint can optionally require authentication:
- Callers present their own ServiceAccount token
- kube-federated-auth validates caller against local cluster
- Provides audit trail and access control

## Performance Considerations

### JWKS Caching

- JWKS are cached per cluster
- Refreshed periodically (configurable)
- Detection is O(N) where N = number of clusters, but each check is fast (local crypto)

### Optimizations

1. **Issuer hint**: Check `iss` claim first to try matching cluster
2. **Parallel detection**: Try all clusters concurrently
3. **Result caching**: Cache successful cluster mappings by ServiceAccount

## Code Changes Summary

### Modified Files

| File | Changes |
|------|---------|
| `internal/handler/tokenreview.go` | Add JWKS detection + TokenReview forwarding |
| `internal/oidc/verifier.go` | Add method to verify without returning claims |

### New Dependencies

- `k8s.io/client-go` for TokenReview forwarding (already present)

## References

- [Kubernetes TokenReview API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
- [Managing Service Accounts](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- [Service Account Token Volume Projection](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#serviceaccount-token-volume-projection)
