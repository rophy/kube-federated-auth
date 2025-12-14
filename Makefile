.PHONY: build kind deploy test-unit test-e2e test destroy clean help

# Build Docker images
build:
	skaffold build -p cluster-a

# Create kind clusters for multi-cluster testing
kind:
	@echo "=========================================="
	@echo "Setting up Kind Clusters"
	@echo "=========================================="
	@./scripts/setup-kind-clusters.sh

# Deploy to multi-cluster environment
# Flow: create clusters → deploy cluster-b → get creds → deploy cluster-a
deploy:
	scripts/setup-kind-clusters.sh
	skaffold run -p cluster-b
	scripts/setup-multicluster.sh
	skaffold run -p cluster-a

# Run unit tests
test-unit:
	go test -v ./internal/...

# Run e2e tests in cluster-a
test-e2e:
	@echo "Running e2e tests in cluster-a..."
	kubectl --context kind-cluster-a exec -n kube-federated-auth deployment/test-client -- go test -v ./test/e2e/...

# Run all tests
test: test-unit test-e2e

# Destroy kind clusters and all deployments
destroy:
	@echo "=========================================="
	@echo "Destroying Multi-Cluster Environment"
	@echo "=========================================="
	@echo ""
	@echo "Removing deployments from cluster-a..."
	@kubectl config use-context kind-cluster-a 2>/dev/null && skaffold delete || echo "Cluster-a not found or already cleaned"
	@echo ""
	@echo "Removing deployments from cluster-b..."
	@kubectl config use-context kind-cluster-b 2>/dev/null && kubectl delete namespace kube-federated-auth --ignore-not-found || echo "Cluster-b not found or already cleaned"
	@echo ""
	@echo "Deleting kind clusters..."
	@kind delete cluster --name cluster-a 2>/dev/null || echo "Cluster-a already deleted"
	@kind delete cluster --name cluster-b 2>/dev/null || echo "Cluster-b already deleted"
	@echo ""
	@echo "Destroy complete!"

# Clean local build artifacts
clean:
	rm -rf bin/

# Show help
help:
	@echo "kube-federated-auth - Cross-Cluster Kubernetes Authentication"
	@echo ""
	@echo "Build targets:"
	@echo "  make build             - Build Docker images"
	@echo "  make clean             - Clean local build artifacts"
	@echo ""
	@echo "Multi-cluster environment:"
	@echo "  make kind              - Create two kind clusters (cluster-a, cluster-b)"
	@echo "  make deploy            - Setup clusters and deploy everything"
	@echo "  make test              - Run all tests (unit + e2e)"
	@echo "  make test-unit         - Run unit tests only"
	@echo "  make test-e2e          - Run e2e tests in cluster-a"
	@echo "  make destroy           - Destroy everything (deployments + clusters)"
	@echo ""
	@echo "Workflow:"
	@echo "  1. make deploy         - Create clusters and deploy service"
	@echo "  2. make test           - Run authentication tests"
	@echo "  3. make destroy        - Destroy clusters when done"
	@echo ""
	@echo "Quick start:"
	@echo "  make deploy && make test"
	@echo ""
	@echo "Architecture:"
	@echo "  - cluster-a: kube-federated-auth service + test-client"
	@echo "  - cluster-b: provides OIDC endpoint for cross-cluster token validation"
	@echo ""
