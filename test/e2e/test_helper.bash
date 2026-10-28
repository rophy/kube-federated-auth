#!/bin/bash
# Common test helpers for kube-federated-auth e2e tests
# Tests run on the HOST and use kubectl exec to reach in-cluster services.

KUBE_CONTEXT="${KUBE_CONTEXT:-kind-cluster-a}"
NAMESPACE="${NAMESPACE:-kube-federated-auth}"
TEST_CLIENT="${TEST_CLIENT:-deployment/test-client}"

KUBE_CONTEXT_B="${KUBE_CONTEXT_B:-kind-cluster-b}"
NAMESPACE_B="${NAMESPACE_B:-kube-federated-auth}"

SERVICE_URL="${SERVICE_URL:-http://kube-federated-auth}"
CLUSTER_NAME="${CLUSTER_NAME:-cluster-a}"
TOKEN_PATH="${TOKEN_PATH:-/var/run/secrets/tokens/token}"

# Run a command in the test-client pod
kexec() {
    kubectl --context "$KUBE_CONTEXT" exec -n "$NAMESPACE" "$TEST_CLIENT" -- "$@"
}

# Read the projected ServiceAccount token from the test-client pod
get_token() {
    kexec cat "$TOKEN_PATH"
}

# Read the caller's own SA token (from the default service account mount)
get_caller_token() {
    kexec cat /var/run/secrets/kubernetes.io/serviceaccount/token
}

# POST a TokenReview request via curl in the test-client pod
# The caller's own SA token is sent as Bearer in Authorization header.
token_review() {
    local token="$1"
    local caller_token
    caller_token=$(get_caller_token)
    kexec curl -s -X POST "${SERVICE_URL}/apis/authentication.k8s.io/v1/tokenreviews" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${caller_token}" \
        -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"${token}\"}}"
}

# Create a short-lived token from cluster-b's reader SA
get_cluster_b_token() {
    kubectl --context "$KUBE_CONTEXT_B" -n "$NAMESPACE_B" create token kube-federated-auth-reader --duration=10m
}

# Create a short-lived token from cluster-b's reader SA with the given audience
get_cluster_b_token_aud() {
    local audience="$1"
    kubectl --context "$KUBE_CONTEXT_B" -n "$NAMESPACE_B" create token kube-federated-auth-reader --duration=10m --audience "$audience"
}

# POST a TokenReview request with spec.audiences
# Usage: token_review_aud <token> '["aud-1","aud-2"]'
token_review_aud() {
    local token="$1"
    local audiences="$2"
    local caller_token
    caller_token=$(get_caller_token)
    kexec curl -s -X POST "${SERVICE_URL}/apis/authentication.k8s.io/v1/tokenreviews" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${caller_token}" \
        -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"${token}\",\"audiences\":${audiences}}}"
}

# Create a token from a SA that is NOT in the authorized_clients whitelist
get_unauthorized_caller_token() {
    kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" create token default --duration=10m
}

# Create a legacy SA token (type: kubernetes.io/service-account-token) for cluster-a
# These tokens have issuer "kubernetes/serviceaccount" instead of the OIDC issuer
get_legacy_sa_token() {
    local sa="${1:-test-client}"
    local secret_name="legacy-sa-token-test"
    # Create a legacy-style Secret bound to the SA
    kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${secret_name}
  annotations:
    kubernetes.io/service-account.name: ${sa}
type: kubernetes.io/service-account-token
EOF
    # Wait for the token controller to populate the token
    local attempts=0
    while [[ $attempts -lt 10 ]]; do
        local token
        token=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get secret "$secret_name" -o jsonpath='{.data.token}' 2>/dev/null)
        if [[ -n "$token" ]]; then
            echo "$token" | base64 -d
            return 0
        fi
        sleep 1
        attempts=$((attempts + 1))
    done
    echo "ERROR: legacy SA token not populated after 10s" >&2
    return 1
}

# Run kubectl against cluster-a in the kube-federated-auth namespace
ka() {
    kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" "$@"
}

# Get logs from the kube-federated-auth server pod
server_logs() {
    ka logs -l app=kube-federated-auth --tail=100
}

# Save the current ConfigMap data for later restore
save_configmap() {
    ka get configmap kube-federated-auth -o jsonpath='{.data.clusters\.yaml}' > "${BATS_SUITE_TMPDIR}/configmap-backup.yaml"
}

# Restore ConfigMap from saved backup and restart deployment
restore_configmap() {
    local backup="${BATS_SUITE_TMPDIR}/configmap-backup.yaml"
    [[ -f "$backup" ]] || return 0
    ka create configmap kube-federated-auth --from-file="clusters.yaml=${backup}" --dry-run=client -o yaml | ka apply -f -
    restart_and_wait
}

# Patch ConfigMap by prepending a YAML field and restart deployment
# Usage: patch_configmap_field "log_level: DEBUG"
patch_configmap_field() {
    local field="$1"
    local current
    current=$(ka get configmap kube-federated-auth -o jsonpath='{.data.clusters\.yaml}')
    local patched
    patched=$(printf '%s\n%s' "$field" "$current")
    ka create configmap kube-federated-auth --from-file=clusters.yaml=<(echo "$patched") --dry-run=client -o yaml | ka apply -f -
    restart_and_wait
}

# Restart the deployment and wait until both health and TokenReview are ready
restart_and_wait() {
    ka rollout restart deployment/kube-federated-auth
    ka rollout status deployment/kube-federated-auth --timeout=60s
    wait_for_service
    wait_for_tokenreview
}

# Get logs from the current kube-federated-auth server pod since a given timestamp
server_logs_since() {
    local since="$1"
    ka logs -l app=kube-federated-auth --since-time="$since"
}

# Wait for the health endpoint to respond (up to 30 seconds)
wait_for_service() {
    local url="${1:-${SERVICE_URL}/health}"
    local attempts=0
    while [[ $attempts -lt 30 ]]; do
        if kexec curl -sf "$url" > /dev/null 2>&1; then
            return 0
        fi
        sleep 1
        attempts=$((attempts + 1))
    done
    echo "ERROR: service not ready at $url" >&2
    return 1
}

# Wait for TokenReview to succeed (up to 30 seconds).
# This warms up the OIDC verifier which lazily fetches JWKS keys on first request.
wait_for_tokenreview() {
    local token
    token=$(get_token)
    local attempts=0
    while [[ $attempts -lt 30 ]]; do
        local result
        result=$(token_review "$token" 2>/dev/null) || true
        local authenticated
        authenticated=$(echo "$result" | jq -r '.status.authenticated' 2>/dev/null) || true
        if [[ "$authenticated" == "true" ]]; then
            return 0
        fi
        sleep 1
        attempts=$((attempts + 1))
    done
    echo "ERROR: TokenReview not ready after 30s" >&2
    return 1
}
