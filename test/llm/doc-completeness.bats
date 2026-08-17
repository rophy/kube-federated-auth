#!/usr/bin/env bats

# Requires: claude CLI, two Kind clusters (make kind)
# Run: make test-llm

setup_file() {
    export IMAGE="${IMAGE:-ghcr.io/rophy/kube-federated-auth:latest}"
    export LOG_DIR="${BATS_TEST_DIRNAME}/logs/doc-completeness"
    mkdir -p "$LOG_DIR"
    local TIMESTAMP
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    export RESULT_FILE="${LOG_DIR}/result-${TIMESTAMP}.txt"
    export GAPS_FILE="${LOG_DIR}/gaps-${TIMESTAMP}.txt"
    export CLAUDE_LOG="${LOG_DIR}/claude-${TIMESTAMP}.log"

    # Clean up any existing deployment
    # Clean up namespaced and cluster-scoped resources from previous runs.
    # The AI creates ClusterRoles/Bindings that survive namespace deletion.
    for ctx in kind-cluster-a kind-cluster-b; do
        kubectl delete namespace kube-federated-auth --context "$ctx" --ignore-not-found
        kubectl delete clusterrole tokenreview-creator --context "$ctx" --ignore-not-found 2>/dev/null || true
        kubectl delete clusterrolebinding kube-federated-auth-tokenreview kube-federated-auth-reader-tokenreview --context "$ctx" --ignore-not-found 2>/dev/null || true
    done

    # Ensure image is available
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        docker pull "$IMAGE"
    fi
}

@test "AI can deploy from container image alone" {
    local PROMPT
    PROMPT="$(cat <<PROMPT_EOF
You have a container image: ${IMAGE}

Two fresh Kind clusters are available:
- kind-cluster-a (kubectl context: kind-cluster-a)
- kind-cluster-b (kubectl context: kind-cluster-b)

Your task:
1. Figure out what this container image does and how to use it
2. Deploy it to the clusters with authorized_clients configured
3. Verify it works by making a successful API request (with caller authentication)
4. Write the final verification response to ${RESULT_FILE}

Important:
- Start by running the container image to discover how to use it
- Do NOT look at any source code repositories or git repos
- You must figure everything out from the container image alone
- If you encounter gaps or unclear instructions, note them in ${GAPS_FILE}
- Always use explicit kubectl context (--context kind-cluster-a or --context kind-cluster-b)
PROMPT_EOF
)"

    claude -p "$PROMPT" \
        --dangerously-skip-permissions \
        --max-budget-usd 5 \
        --allowedTools "Bash Read Write" \
        2>&1 | tee "${CLAUDE_LOG}"

    # Verify result file exists and AI claims success
    [ -f "$RESULT_FILE" ]
    grep -qi 'authenticated.*true' "$RESULT_FILE"

    # Independent verification
    local token
    token=$(kubectl create token default --context kind-cluster-b -n default --duration=10m)
    local caller_token
    caller_token=$(kubectl create token kube-federated-auth --context kind-cluster-a -n kube-federated-auth --duration=10m)

    # Verify authorized_clients is enforced: request without caller token should fail
    local no_auth_result
    no_auth_result=$(kubectl run curl-noauth --rm -i --restart=Never \
        --context kind-cluster-a -n kube-federated-auth \
        --image=curlimages/curl -- \
        curl -s -X POST http://kube-federated-auth:8080/apis/authentication.k8s.io/v1/tokenreviews \
        -H "Content-Type: application/json" \
        -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"${token}\"}}")
    echo "# No-auth result: $no_auth_result"
    echo "$no_auth_result" | grep -q '"error"'

    # Verify authenticated TokenReview with caller token succeeds
    local result
    result=$(kubectl run curl-auth --rm -i --restart=Never \
        --context kind-cluster-a -n kube-federated-auth \
        --image=curlimages/curl -- \
        curl -s -X POST http://kube-federated-auth:8080/apis/authentication.k8s.io/v1/tokenreviews \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${caller_token}" \
        -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"${token}\"}}")
    echo "# Auth result: $result"
    echo "$result" | grep -q '"authenticated":true\|"authenticated": true'
}
