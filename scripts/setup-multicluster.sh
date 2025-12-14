#!/bin/bash
# Setup multi-cluster authentication
# This script runs AFTER cluster-b is deployed, BEFORE cluster-a is deployed
# It creates the bootstrap credentials secret in cluster-a (only if it doesn't exist)
set -e

CLUSTER_A="cluster-a"
CLUSTER_B="cluster-b"
NAMESPACE="multi-k8s-auth"
SECRET_NAME="multi-k8s-auth"

echo "=========================================="
echo "Configuring Multi-Cluster Authentication"
echo "=========================================="
echo ""

# Read existing IPs from skaffold.env
source skaffold.env
echo "Cluster-A API Server IP: $CLUSTER_A_IP"
echo "Cluster-B API Server IP: $CLUSTER_B_IP"

# Check if secret already exists in cluster-a
if kubectl --context=kind-${CLUSTER_A} --namespace=${NAMESPACE} get secret ${SECRET_NAME} >/dev/null 2>&1; then
  echo "✅ Credentials secret already exists in cluster-a, skipping bootstrap"
  TOKEN=$(kubectl --context=kind-${CLUSTER_A} --namespace=${NAMESPACE} get secret ${SECRET_NAME} -o jsonpath='{.data.cluster-b-token}' | base64 -d)
else
  echo "Creating bootstrap credentials..."

  # Create a bootstrap token from the reader service account
  echo "  Creating bootstrap token from cluster-b..."
  TOKEN=$(kubectl --context=kind-${CLUSTER_B} --namespace=${NAMESPACE} create token multi-k8s-auth-reader --duration=168h)
  echo "  ✅ Bootstrap token created (7 day TTL)"

  # Extract CA certificate
  echo "  Extracting CA certificate from cluster-b..."
  CA_CERT=$(kubectl --context=kind-${CLUSTER_B} get configmap kube-root-ca.crt -n kube-system -o jsonpath='{.data.ca\.crt}')
  echo "  ✅ CA certificate extracted"

  # Create namespace in cluster-a if it doesn't exist
  kubectl --context=kind-${CLUSTER_A} create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl --context=kind-${CLUSTER_A} apply -f -

  # Create the secret in cluster-a
  echo "  Creating credentials secret in cluster-a..."
  kubectl --context=kind-${CLUSTER_A} --namespace=${NAMESPACE} create secret generic ${SECRET_NAME} \
    --from-literal=cluster-b-token="${TOKEN}" \
    --from-literal=cluster-b-ca.crt="${CA_CERT}"
  echo "  ✅ Credentials secret created"
fi

# Get issuer from token (needed for skaffold.env)
if ! grep -q "^ISSUER=" skaffold.env 2>/dev/null; then
  ISSUER=$(echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq -r '.iss')
  echo "ISSUER=$ISSUER" >> skaffold.env
  echo "Cluster-B Issuer: $ISSUER"
fi

echo ""
echo "=========================================="
echo "✅ Multi-Cluster Configuration Complete"
echo "=========================================="
echo ""
echo "Summary:"
echo "  Cluster-A API: https://${CLUSTER_A_IP}:6443"
echo "  Cluster-B API: https://${CLUSTER_B_IP}:6443"
echo "  Service URL:   http://${CLUSTER_A_IP}:30080"
echo ""
