# kube-federated-auth

**Authenticate workloads across multiple Kubernetes clusters using OIDC-compliant ServiceAccount tokens with explicit issuer trust.**

---

## Overview

`kube-federated-auth` enables secure, cross-cluster workload authentication for Kubernetes services. Workloads running in one cluster can authenticate to services in another cluster using **ServiceAccount JWTs**, without requiring additional secrets or control planes.

Key benefits:
- Cross-cluster authentication
- Kubernetes-native identity delegation
- Explicit, auditable trust
- Automated credential lifecycle management
- Low operational complexity

---

## Architecture

```
cluster-a (service cluster)              cluster-b (client cluster)
┌────────────────────────────────────┐   ┌─────────────────────────────────┐
│                                    │   │                                 │
│  ┌──────────┐    ┌──────────────┐  │   │  ┌─────────┐                    │
│  │ db-svc   │───▶│kube-federated-auth│  │   │  │ client  │ (has SA token)     │
│  └──────────┘    └──────────────┘  │   │  └────┬────┘                    │
│       ▲                │           │   │       │                         │
│       │                │ validates │   │       │ connects to db-svc      │
│       │                ▼           │   │       │ with SA token           │
│       │         ┌────────────┐     │   │       │                         │
│       │         │ cluster-a  │     │   └───────┼─────────────────────────┘
│       │         │ OIDC       │     │           │
│       │         └────────────┘     │           │
│       │                │           │           │
│       │                │           │           │
│       │         ┌────────────┐     │           │
│       │         │ cluster-b  │◀────┼───────────┘
│       │         │ OIDC       │     │
│       │         └────────────┘     │
│       │                            │
│       └────────────────────────────┼───────────┘
│                                    │
│  ┌──────────────────────────────┐  │   ┌─────────────────────────────────┐
│  │ Secret: credentials          │  │   │  kube-federated-auth-agent           │
│  │   cluster-b-token: <token>   │◀─┼───│  (pushes fresh credentials)     │
│  │   cluster-b-ca.crt: <cert>   │  │   │                                 │
│  └──────────────────────────────┘  │   └─────────────────────────────────┘
│                                    │
└────────────────────────────────────┘
```

**Components:**
- **kube-federated-auth**: Token validation service, co-located with services needing authentication
- **kube-federated-auth-agent**: Deployed in remote clusters, pushes fresh credentials to kube-federated-auth
- **db-svc**: Example service (e.g., database) that delegates authentication to kube-federated-auth

**Assumptions:**
- Services (db-svc) and kube-federated-auth are deployed in the same cluster
- Clients from any cluster connect to services, authenticating with their SA tokens
- kube-federated-auth validates tokens from all configured clusters

---

## Goals

- **Enable secure workload identity verification across Kubernetes clusters**
- **Delegate authentication to Kubernetes ServiceAccounts**, leveraging OIDC-compliant JWTs
- **Automate credential lifecycle** for accessing remote cluster OIDC endpoints
- **Maintain minimal operational overhead**, avoiding service meshes or SPIFFE control planes
- **Provide explicit trust configuration** for each cluster to prevent accidental trust expansion

---

## Rationale

Kubernetes ServiceAccounts provide a strong local identity mechanism. However, there is **no built-in cross-cluster authentication**. Existing solutions like SPIFFE or Istio provide robust identity federation but come with significant operational complexity.

`kube-federated-auth` leverages:
- **Kubernetes as OIDC Identity Provider**
- **ServiceAccount projected JWTs**
- **Explicit trust per cluster**
- **Agent-based credential refresh** for secure, automated operations

This approach allows cross-cluster workload authentication **without introducing new secrets or infrastructure**, while remaining auditable and secure.

---

## Concepts

### ServiceAccount as Identity

- Each ServiceAccount issues a JWT via the Kubernetes API server.
- Standard claims include:
  - `iss`: Issuer URL (API server)
  - `sub`: ServiceAccount identity (`system:serviceaccount:<namespace>:<name>`)
  - `aud`: Intended audience (service)
  - `exp`: Expiration timestamp

### Cross-Cluster Trust

- Each remote cluster is an explicit OIDC issuer.
- Services verify JWTs using:
  - Signature validation via JWKS
  - `iss` and `aud` verification
  - Token expiration (`exp`)
- Only explicitly trusted clusters can authenticate.

### Authentication Flow

1. **Client workload** obtains a projected ServiceAccount token.
2. **Client** sends the token to the target service over TLS.
3. **Service** calls kube-federated-auth `/validate` API with token + cluster name.
4. **kube-federated-auth** validates the JWT:
   - Verifies signature against issuer JWKS
   - Checks `iss` claim matches configured issuer
   - Ensures token is not expired
5. **kube-federated-auth** returns validated claims to service.
6. **Service** applies authorization based on claims.

---

## Credential Lifecycle Management

kube-federated-auth needs credentials to access remote cluster OIDC endpoints (for JWKS). These credentials are managed automatically via the agent pattern.

### Credential Flow

```
1. Bootstrap (manual, one-time):
   ┌─────────────────────────────────────────────────────────────┐
   │ Admin creates bootstrap token for cluster-b (TTL=7d)       │
   │ kubectl create token kube-federated-auth-agent --duration=168h  │
   │ Configures kube-federated-auth with bootstrap credentials       │
   └─────────────────────────────────────────────────────────────┘

2. Agent Refresh (automated, periodic):
   ┌──────────────────┐                    ┌──────────────────┐
   │ kube-federated-auth   │◀── POST /register ─│ agent (cluster-b)│
   │ (cluster-a)      │    + SA token      │                  │
   │                  │    + CA cert       │ runs periodically│
   │                  │                    │                  │
   │ validates agent, │                    │                  │
   │ stores creds,    │                    │                  │
   │ persists to      │                    │                  │
   │ K8s Secret       │                    │                  │
   └──────────────────┘                    └──────────────────┘
```

### Credential Persistence

kube-federated-auth persists credentials to a Kubernetes Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kube-federated-auth-credentials
  namespace: kube-federated-auth
type: Opaque
data:
  cluster-b-token: <base64>
  cluster-b-ca.crt: <base64>
```

**Fallback chain on startup:**
1. In-memory credentials (freshest)
2. Persisted Secret (survives restart)
3. Bootstrap config (initial setup / recovery)

### Agent Authorization

Not any token from a remote cluster can push credentials. The agent must authenticate as a specific ServiceAccount:

```yaml
# Only this identity can register credentials
allowedAgents:
  cluster-b: "system:serviceaccount:kube-federated-auth:kube-federated-auth-agent"
```

---

## Security Considerations / Threat Model

- **Identity Impersonation:** Prevented by JWT signature verification and explicit issuer trust.
- **Replay Attacks:** Mitigated via short-lived tokens and audience validation.
- **Man-in-the-Middle (MITM):** TLS required for token transport.
- **Key Compromise:** Only trusted clusters’ API servers are allowed; key rotation is recommended.
- **Token Expiration / Revocation:** Tokens are short-lived; real-time revocation not supported.

---

## Getting Started

Example workflow:

1. Project ServiceAccount token in client pod:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: client
spec:
  serviceAccountName: client-sa
  containers:
  - name: app
    image: myapp
    volumeMounts:
      - name: sa-token
        mountPath: /var/run/secrets/tokens
  volumes:
    - name: sa-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              expirationSeconds: 600
              audience: myservice
````

2. Client sends token to service over HTTPS:

```bash
curl -H "Authorization: Bearer $(cat /var/run/secrets/tokens/token)" https://service.cluster-a.local
```

3. Service verifies JWT and maps `sub` claim to internal identity.

---

## Components

| Component | Description | Deployment |
|-----------|-------------|------------|
| `kube-federated-auth` | Token validation service | Service cluster |
| `kube-federated-auth-agent` | Credential refresh agent | Each remote cluster |

## Roadmap / Future Work

* mTLS integration for transport security
* SDK / library for easy token verification in multiple languages
* Example integrations with databases and HTTP services

---

## License

MIT License

