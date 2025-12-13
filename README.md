# multi-k8s-auth

**Authenticate workloads across multiple Kubernetes clusters using OIDC-compliant ServiceAccount tokens with explicit issuer trust.**

---

## Overview

`multi-k8s-auth` enables secure, cross-cluster workload authentication for Kubernetes services. Workloads running in one cluster can authenticate to services in another cluster using **ServiceAccount JWTs**, without requiring additional secrets or control planes.

Key benefits:
- Cross-cluster authentication
- Kubernetes-native identity delegation
- Explicit, auditable trust
- Low operational complexity

---

## Goals

- **Enable secure workload identity verification across Kubernetes clusters**  
- **Delegate authentication to Kubernetes ServiceAccounts**, leveraging OIDC-compliant JWTs  
- **Maintain minimal operational overhead**, avoiding service meshes or SPIFFE control planes  
- **Provide explicit trust configuration** for each cluster to prevent accidental trust expansion  

---

## Rationale

Kubernetes ServiceAccounts provide a strong local identity mechanism. However, there is **no built-in cross-cluster authentication**. Existing solutions like SPIFFE or Istio provide robust identity federation but come with significant operational complexity.

`multi-k8s-auth` leverages:
- **Kubernetes as OIDC Identity Provider**
- **ServiceAccount projected JWTs**
- **Explicit trust per cluster**

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
3. **Service** validates the JWT:
   - Verifies signature against issuer JWKS
   - Checks `iss` and `aud` claims
   - Ensures token is not expired  
4. **Service** maps `sub` claim to internal identity.  
5. Authorization is applied based on mapped identity.

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

## Roadmap / Future Work

* Optional mTLS integration for transport security
* Multi-issuer federation support
* SDK / library for easy token verification in multiple languages
* Example integrations with databases and HTTP services

---

## License

MIT License

