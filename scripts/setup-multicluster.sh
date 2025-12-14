#!/bin/bash
# Setup multi-cluster authentication
# This script runs AFTER cluster-b is deployed, BEFORE cluster-a is deployed
# It extracts cluster-b credentials and appends to skaffold.env
set -e

CLUSTER_A="cluster-a"
CLUSTER_B="cluster-b"
NAMESPACE="multi-k8s-auth"

echo "=========================================="
echo "Configuring Multi-Cluster Authentication"
echo "=========================================="
echo ""

# Read existing IPs from skaffold.env
source skaffold.env
echo "Cluster-A API Server IP: $CLUSTER_A_IP"
echo "Cluster-B API Server IP: $CLUSTER_B_IP"

# Create a bootstrap token from the agent service account for accessing cluster-b OIDC endpoints
TOKEN_FILE="/tmp/cluster-b-token.txt"
kubectl --context=kind-${CLUSTER_B} --namespace=${NAMESPACE} create token multi-k8s-auth-agent --duration=168h > "$TOKEN_FILE"
echo "BOOTSTRAP_TOKEN=$(cat $TOKEN_FILE | base64 -w0)" >> skaffold.env
echo "✅ Bootstrap token created (7 day TTL)"

# Extract CA certificate
CA_FILE="/tmp/cluster-b-ca.crt"
kubectl --context=kind-${CLUSTER_B} get configmap kube-root-ca.crt -n kube-system -o jsonpath='{.data.ca\.crt}' > "$CA_FILE"
echo "CA_CERT=$(cat $CA_FILE | base64 -w0)" >> skaffold.env
echo "✅ CA certificate extracted"

# Get issuer from token
ISSUER=$(cat "$TOKEN_FILE" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq -r '.iss')
echo "ISSUER=$ISSUER" >> skaffold.env
echo "Cluster-B Issuer: $ISSUER"

# Does the secret exist?
kubectl get secret multi-k8s-auth --context=kind-${CLUSTER_A} --namespace=${NAMESPACE} >/dev/null 2>&1 && CREATE_SECRET=false || CREATE_SECRET=true
echo "CREATE_SECRET=${CREATE_SECRET}" >> skaffold.env

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
