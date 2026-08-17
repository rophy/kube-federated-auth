#!/bin/bash
# Documentation completeness test
#
# Verifies that an AI agent can discover how to use kube-federated-auth
# starting from just the container image — no pre-fed documentation.
#
# The AI is expected to:
#   1. Run the container image and discover the -help flag
#   2. Read the documentation via -help
#   3. Deploy the system to two Kind clusters
#   4. Verify a cross-cluster TokenReview
#
# Prerequisites: kind, docker, claude CLI
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "$LOG_DIR"

IMAGE="${IMAGE:-ghcr.io/rophy/kube-federated-auth:latest}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
CLAUDE_LOG="${LOG_DIR}/claude-${TIMESTAMP}.log"
RESULT_FILE="${LOG_DIR}/result-${TIMESTAMP}.txt"

echo "=== Documentation Completeness Test ==="
echo "Image: ${IMAGE}"
echo "Log:   ${CLAUDE_LOG}"
echo ""

# Step 1: Clean up any existing test clusters
echo "Step 1: Cleaning up existing clusters..."
kind delete cluster --name cluster-a 2>/dev/null || true
kind delete cluster --name cluster-b 2>/dev/null || true
echo "Done."
echo ""

# Step 2: Create fresh Kind clusters
echo "Step 2: Creating fresh Kind clusters..."
kind create cluster --name cluster-a --wait 5m
kind create cluster --name cluster-b --wait 5m
echo "Done."
echo ""

# Step 3: Pull the image (skip if already available locally)
echo "Step 3: Checking container image..."
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Image already available locally."
else
  docker pull "$IMAGE"
fi
echo "Done."
echo ""

# Step 4: Run Claude
echo "Step 4: Running Claude to deploy from container image alone..."
echo "This may take several minutes."
echo ""

PROMPT="$(cat <<PROMPT_EOF
You have a container image: ${IMAGE}

Two fresh Kind clusters are available:
- kind-cluster-a (kubectl context: kind-cluster-a)
- kind-cluster-b (kubectl context: kind-cluster-b)

Your task:
1. Figure out what this container image does and how to use it
2. Deploy it to the clusters
3. Verify it works by making a successful API request
4. Write the final verification response to /tmp/doc-test-result.txt

Important:
- Start by running the container image to discover how to use it
- Do NOT look at any source code repositories or git repos
- You must figure everything out from the container image alone
- If you encounter gaps or unclear instructions, note them in /tmp/doc-test-gaps.txt
- Always use explicit kubectl context (--context kind-cluster-a or --context kind-cluster-b)
PROMPT_EOF
)"

claude -p "$PROMPT" \
  --dangerously-skip-permissions \
  --max-budget-usd 5 \
  --allowedTools "Bash Read Write" \
  2>&1 | tee "$CLAUDE_LOG"

echo ""
echo "=== Results ==="

if [ -f /tmp/doc-test-result.txt ]; then
  echo "Verification result:"
  cat /tmp/doc-test-result.txt
  cp /tmp/doc-test-result.txt "$RESULT_FILE"
  echo ""

  if grep -qi 'authenticated.*true' /tmp/doc-test-result.txt 2>/dev/null; then
    echo "PASS: AI successfully deployed from container image alone"
  else
    echo "FAIL: Verification did not return authenticated: true"
  fi
else
  echo "FAIL: AI did not produce /tmp/doc-test-result.txt"
fi

if [ -f /tmp/doc-test-gaps.txt ]; then
  echo ""
  echo "Documentation gaps reported by AI:"
  cat /tmp/doc-test-gaps.txt
fi

echo ""
echo "Full Claude log: ${CLAUDE_LOG}"
