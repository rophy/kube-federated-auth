# kube-federated-auth Design

## Overview

A Go service that validates Kubernetes ServiceAccount JWT tokens across multiple clusters using OIDC discovery, with automated credential lifecycle management.

## System Architecture

```
cluster-a (service cluster)                 cluster-b (client cluster)
┌─────────────────────────────────────┐     ┌─────────────────────────────┐
│                                     │     │                             │
│  ┌──────────┐    ┌──────────────┐   │     │  ┌─────────┐                │
│  │ db-svc   │───▶│kube-federated-auth│   │     │  │ client  │                │
│  └──────────┘    └──────────────┘   │     │  └────┬────┘                │
│       ▲                │            │     │       │                     │
│       │                │ validates  │     │       │ connects with       │
│       │                ▼            │     │       │ SA token            │
│       │         ┌────────────┐      │     │       │                     │
│       │         │ cluster-a  │      │     └───────┼─────────────────────┘
│       │         │ OIDC       │      │             │
│       │         └────────────┘      │             │
│       │         ┌────────────┐      │             │
│       │         │ cluster-b  │◀─────┼─────────────┘
│       │         │ OIDC       │      │
│       │         └────────────┘      │
│       │                             │
│       └─────────────────────────────┼─────────────┘
│                                     │
│  ┌───────────────────────────────┐  │     ┌─────────────────────────────┐
│  │ Secret: credentials           │  │     │ kube-federated-auth-agent        │
│  │   cluster-b-token: <token>    │◀─┼─────│ (pushes fresh credentials)  │
│  │   cluster-b-ca.crt: <cert>    │  │     │                             │
│  └───────────────────────────────┘  │     └─────────────────────────────┘
│                                     │
└─────────────────────────────────────┘
```

**Assumptions:**
- Services (e.g., db-svc) and kube-federated-auth are co-located in the same cluster
- Clients from any cluster connect to services with their SA tokens
- Services delegate authentication to kube-federated-auth

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     kube-federated-auth                          │
├─────────────────────────────────────────────────────────────┤
│  Config (YAML)                                              │
│  ┌─────────────┬──────────────────────────────────────┐    │
│  │ cluster-a   │ issuer: https://oidc.eks...          │    │
│  │ cluster-b   │ issuer: https://k8s.internal.corp    │    │
│  │             │ ca_cert: /path/to/ca.crt             │    │
│  │             │ token_path: /path/to/token           │    │
│  └─────────────┴──────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│  POST /validate                                             │
│  ┌─────────────────┐        ┌────────────────────────┐     │
│  │ Request:        │        │ Response:              │     │
│  │   cluster: "a"  │  ───►  │   cluster: "cluster-a" │     │
│  │   token: "eyJ.."│        │   iss: "https://..."   │     │
│  └─────────────────┘        │   sub: "system:sa:..." │     │
│                             │   aud: [...]           │     │
│          │                  │   kubernetes.io: {...} │     │
│          ▼                  └────────────────────────┘     │
│  ┌─────────────────┐                                       │
│  │ OIDC Verifiers  │ ◄── Fetches JWKS from issuers        │
│  │ (per cluster)   │                                       │
│  └─────────────────┘                                       │
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

### POST /validate

Validate a Kubernetes ServiceAccount token.

**Request:**
```json
{
  "cluster": "cluster-a",
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ii..."
}
```

**Response (200 OK):**
```json
{
  "cluster": "cluster-a",
  "iss": "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE",
  "sub": "system:serviceaccount:my-namespace:my-sa",
  "aud": ["my-service"],
  "exp": 1702500000,
  "iat": 1702496400,
  "nbf": 1702496400,
  "kubernetes.io": {
    "namespace": "my-namespace",
    "serviceaccount": {
      "name": "my-sa",
      "uid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    },
    "pod": {
      "name": "my-pod-xyz",
      "uid": "e5f6g7h8-i9j0-1234-klmn-opqrstuvwxyz"
    }
  }
}
```

**Error Response (400 Bad Request):**
```json
{
  "error": "cluster_not_found",
  "message": "No configuration found for cluster: unknown-cluster"
}
```

**Error Response (401 Unauthorized):**
```json
{
  "error": "invalid_signature",
  "message": "Token signature verification failed"
}
```

### GET /health

Health check for liveness/readiness probes.

**Response (200 OK):**
```json
{
  "status": "ok"
}
```

### GET /clusters

List configured cluster names.

**Response (200 OK):**
```json
{
  "clusters": ["cluster-a", "cluster-b", "eks-prod"]
}
```

## Configuration

### Format

```yaml
clusters:
  # Public cloud cluster (uses public CA, public OIDC endpoint)
  eks-prod:
    issuer: "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE"

  # Self-hosted cluster with private CA
  internal:
    issuer: "https://k8s.internal.corp"
    ca_cert: "/path/to/internal-ca.crt"

  # Cluster with protected OIDC endpoint (requires auth)
  minikube:
    issuer: "https://kubernetes.default.svc.cluster.local"
    ca_cert: "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    token_path: "/var/run/secrets/kubernetes.io/serviceaccount/token"
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `issuer` | Yes | OIDC issuer URL (used for discovery and JWKS) |
| `ca_cert` | No | Path to CA certificate file for TLS verification |
| `token_path` | No | Path to bearer token for authenticating to OIDC endpoint |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server listening port |
| `CONFIG_PATH` | `config/clusters.yaml` | Path to cluster config file |

## Credential Lifecycle Management

kube-federated-auth needs credentials (token + CA cert) to access remote cluster OIDC endpoints for JWKS fetching. These credentials are managed via the agent pattern.

### Why Agent Pattern?

| Approach | Security | Complexity | Automation |
|----------|----------|------------|------------|
| Long-lived tokens | Low | Low | None |
| Bootstrap + self-refresh | Medium | Medium | Partial |
| **Agent pattern** | **High** | **Medium** | **Full** |

The agent pattern allows:
- Short-lived tokens (hours, not days)
- No long-lived credentials crossing network boundaries
- Full automation after bootstrap

### Credential Flow

```
Phase 1: Bootstrap (manual, one-time per cluster)
───────────────────────────────────────────────────
Admin creates bootstrap token:
  kubectl create token kube-federated-auth-agent -n kube-federated-auth --duration=168h

Configure kube-federated-auth with bootstrap credentials (TTL=7d)


Phase 2: Agent Registration (automated)
───────────────────────────────────────────────────
┌──────────────────────┐                    ┌────────────────────────┐
│  kube-federated-auth      │                    │  agent (cluster-b)     │
│  (cluster-a)         │                    │                        │
│                      │  POST /register    │                        │
│                      │◀───────────────────│  Sends:                │
│  1. Validate agent   │   + agent SA token │  - Its own SA token    │
│     token using      │   + fresh creds    │  - Fresh OIDC creds    │
│     bootstrap creds  │                    │    (token + CA cert)   │
│                      │                    │                        │
│  2. Check agent is   │                    │                        │
│     authorized SA    │                    │                        │
│                      │                    │                        │
│  3. Accept & store   │                    │                        │
│     fresh creds      │                    │                        │
└──────────────────────┘                    └────────────────────────┘


Phase 3: Continuous Refresh (automated)
───────────────────────────────────────────────────
Agent calls POST /register every hour with fresh credentials.
kube-federated-auth validates using current credentials (not bootstrap).
Self-sustaining cycle - no long-lived credentials needed.
```

### Credential Persistence

kube-federated-auth persists credentials to a Kubernetes Secret (requires RBAC):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kube-federated-auth-credentials
  namespace: kube-federated-auth
type: Opaque
data:
  cluster-b-token: <base64-encoded-token>
  cluster-b-ca.crt: <base64-encoded-cert>
  cluster-c-token: <base64-encoded-token>
  cluster-c-ca.crt: <base64-encoded-cert>
```

**Credential resolution order (on startup and refresh):**
1. In-memory (freshest, from agent push)
2. Kubernetes Secret (persisted, survives restart)
3. Bootstrap config file (initial setup / disaster recovery)

### Agent Authorization

Only specific ServiceAccounts can register credentials:

```yaml
# Config: allowed agents per cluster
agents:
  cluster-b:
    serviceAccount: "system:serviceaccount:kube-federated-auth:kube-federated-auth-agent"
  cluster-c:
    serviceAccount: "system:serviceaccount:kube-federated-auth:kube-federated-auth-agent"
```

### POST /register API

**Request:**
```json
{
  "cluster": "cluster-b",
  "credentials": {
    "token": "eyJhbGciOiJSUzI1NiIs...",
    "ca_cert": "-----BEGIN CERTIFICATE-----\n..."
  }
}
```

**Headers:**
```
Authorization: Bearer <agent-sa-token>
```

**Response (200 OK):**
```json
{
  "status": "accepted",
  "cluster": "cluster-b",
  "expires_at": "2024-01-15T12:00:00Z"
}
```

**Error Response (401 Unauthorized):**
```json
{
  "error": "unauthorized_agent",
  "message": "ServiceAccount not authorized to register credentials for cluster-b"
}
```

### Failure Scenarios

| Scenario | Behavior |
|----------|----------|
| Agent dies | Credentials expire, falls back to bootstrap, alerts |
| kube-federated-auth restarts | Reads from persisted Secret |
| Bootstrap expires before agent connects | Manual intervention required |
| Network partition | Agent retries, credentials eventually expire |

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Missing or malformed request body |
| `cluster_not_found` | 400 | Cluster name not in configuration |
| `invalid_token` | 401 | Malformed JWT |
| `invalid_signature` | 401 | Signature verification failed |
| `token_expired` | 401 | Token has expired |
| `jwks_fetch_failed` | 500 | Failed to fetch JWKS from issuer |
| `oidc_discovery_failed` | 500 | Failed to fetch OIDC discovery document |

## Project Structure

```
kube-federated-auth/
├── cmd/
│   ├── server/
│   │   └── main.go                # kube-federated-auth entry point
│   └── agent/
│       └── main.go                # kube-federated-auth-agent entry point
├── internal/
│   ├── config/
│   │   ├── config.go              # YAML config loading
│   │   └── config_test.go         # Unit tests
│   ├── handler/
│   │   ├── validate.go            # POST /validate
│   │   ├── register.go            # POST /register (agent credentials)
│   │   ├── health.go              # GET /health
│   │   ├── clusters.go            # GET /clusters
│   │   └── handler_test.go        # Unit tests
│   ├── oidc/
│   │   └── verifier.go            # OIDC verifier per cluster
│   ├── credentials/
│   │   ├── store.go               # Credential storage interface
│   │   ├── memory.go              # In-memory credential store
│   │   └── secret.go              # Kubernetes Secret persistence
│   └── server/
│       └── server.go              # HTTP server, routing
├── test/
│   └── e2e/
│       └── e2e_test.go            # End-to-end tests
├── k8s/
│   ├── cluster-a/                 # Service cluster manifests
│   │   ├── namespace.yaml
│   │   ├── serviceaccount.yaml
│   │   ├── rbac.yaml              # RBAC for Secret management
│   │   ├── configmap.yaml
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── test-client.yaml
│   └── cluster-b/                 # Client cluster manifests
│       ├── namespace.yaml
│       ├── serviceaccount.yaml    # For agent
│       └── agent.yaml             # kube-federated-auth-agent deployment
├── config/
│   └── clusters.example.yaml
├── go.mod
├── Dockerfile
├── Dockerfile.agent
├── Dockerfile.test
├── Makefile
├── skaffold.yaml
└── README.md
```

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `github.com/go-chi/chi/v5` | v5.x | HTTP routing and middleware |
| `github.com/coreos/go-oidc/v3` | v3.x | OIDC discovery, JWKS, JWT validation |
| `gopkg.in/yaml.v3` | v3.x | Configuration parsing |

## Development

### Prerequisites

- Go 1.24+
- Docker
- kubectl
- Skaffold
- minikube (or other Kubernetes cluster)

### Commands

```bash
make build       # Build Docker images
make deploy      # Deploy to Kubernetes
make test-unit   # Run unit tests
make test-e2e    # Run e2e tests in cluster
make test        # Run all tests
make clean       # Delete deployed resources
```

### Running E2E Tests

E2E tests run inside the Kubernetes cluster:

```bash
# Deploy first
make deploy

# Run e2e tests
make test-e2e
```

## Authentication Flow

1. Client pod obtains projected ServiceAccount token with custom audience
2. Client sends token to kube-federated-auth with cluster name
3. Service looks up cluster configuration
4. Service validates token using OIDC discovery and JWKS from issuer
5. Service returns decoded claims with cluster name added
6. Caller uses claims for authorization decisions

## Security Considerations

- Only explicitly configured clusters are trusted
- JWKS fetched over TLS (custom CA supported)
- Tokens validated for signature and expiration
- Audience claim returned for caller to validate
- No secrets stored - relies on JWKS endpoints

### Protected OIDC Endpoints

Some Kubernetes clusters (e.g., minikube) protect their OIDC discovery endpoints with authentication. Use `token_path` to provide a ServiceAccount token for authenticating to these endpoints.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Response format | Full JWT claims | Preserves all info, caller decides what to use |
| Issuer in response | Original URL | OIDC-compliant, cluster name added separately |
| Audience validation | Caller responsibility | Authentication only, not authorization |
| Config format | YAML with issuer URL | Standard OIDC approach, works with all K8s distributions |
| CA certificate | File path only | Simple, works with mounted secrets |
| Token auth | Optional `token_path` | Supports protected OIDC endpoints |
| Credential management | Agent pattern | Most secure, fully automated after bootstrap |
| Credential persistence | Kubernetes Secret | Native K8s, survives restarts, no external deps |
| Agent authorization | Specific ServiceAccount | Prevents unauthorized credential injection |
| Deployment model | Co-located with service | Simplifies networking, shared lifecycle |
