.PHONY: build deploy test-unit test-e2e test clean

build:
	skaffold build

deploy:
	skaffold run

test-unit:
	go test -v ./internal/...

test-e2e:
	kubectl exec -n multi-k8s-auth deployment/test-client -- go test -v ./test/e2e/...

test: test-unit test-e2e

clean:
	skaffold delete
