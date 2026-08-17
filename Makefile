.PHONY: build image kind deploy test-unit test-e2e test test-perf destroy clean help

.DEFAULT_GOAL := help

## Build

build: ## Build Docker images (local dev)
	skaffold build -p cluster-a

image: ## Build release image
	./scripts/build-image.sh

clean: ## Clean local build artifacts
	rm -rf bin/

## Cluster

kind: ## Create Kind clusters (cluster-a, cluster-b)
	./scripts/setup-kind-clusters.sh

deploy: ## Setup clusters and deploy everything
	scripts/setup-kind-clusters.sh
	skaffold run -p cluster-b
	scripts/setup-multicluster.sh
	skaffold run -p cluster-a

destroy: ## Destroy Kind clusters and all deployments
	@echo "Removing deployments from cluster-a..."
	@kubectl config use-context kind-cluster-a 2>/dev/null && skaffold delete || echo "Cluster-a not found or already cleaned"
	@echo "Removing deployments from cluster-b..."
	@kubectl config use-context kind-cluster-b 2>/dev/null && kubectl delete namespace kube-federated-auth --ignore-not-found || echo "Cluster-b not found or already cleaned"
	@echo "Deleting kind clusters..."
	@kind delete cluster --name cluster-a 2>/dev/null || echo "Cluster-a already deleted"
	@kind delete cluster --name cluster-b 2>/dev/null || echo "Cluster-b already deleted"

## Test

test: test-unit test-e2e ## Run all tests (unit + e2e)

test-unit: ## Run unit tests
	go test -v ./internal/...

test-e2e: ## Run e2e tests
	bats test/e2e/

test-llm: ## Run LLM-based tests (requires claude CLI)
	docker build -t kube-federated-auth:local .
	IMAGE=kube-federated-auth:local bats test/llm/

test-perf: ## Run k6 performance tests
	bash test/perf/run.sh

## Help

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
