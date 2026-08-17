#!/usr/bin/env bats

# bats test_tags=llm
# Requires: claude CLI, two Kind clusters (make kind)
# Run: make test-e2e-llm

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
    kubectl delete namespace kube-federated-auth --context kind-cluster-a --ignore-not-found
    kubectl delete namespace kube-federated-auth --context kind-cluster-b --ignore-not-found

    # Ensure image is available
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        docker pull "$IMAGE"
    fi
}

# bats test_tags=llm
@test "AI can deploy from container image alone" {
    local PROMPT
    PROMPT="$(cat <<PROMPT_EOF
You have a container image: ${IMAGE}

Two fresh Kind clusters are available:
- kind-cluster-a (kubectl context: kind-cluster-a)
- kind-cluster-b (kubectl context: kind-cluster-b)

Your task:
1. Figure out what this container image does and how to use it
2. Deploy it to the clusters
3. Verify it works by making a successful API request
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

    # Verify result file exists
    [ -f "$RESULT_FILE" ]

    # Verify authenticated: true appears in result
    grep -qi 'authenticated.*true' "$RESULT_FILE"
}
