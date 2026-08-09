# Agents Guide

Guidance for AI agents working on this codebase. See [README.md](README.md) for project overview, API docs, and configuration.

## Quick Commands

```bash
go build ./...              # Build
go test ./internal/...      # Unit tests
make deploy                 # Setup Kind clusters and deploy
bats test/e2e/              # E2E tests (requires Kind clusters)
bash test/perf/run.sh       # Performance tests (requires Kind clusters)

# Check server logs
kubectl logs -n kube-federated-auth deploy/kube-federated-auth --context kind-cluster-a
```

See [test/README.md](test/README.md) for full details on test suites and scenarios.

## Prerequisites

This project uses [mise](https://mise.jdx.dev/) to manage tool versions (see `mise.toml`). The user should activate mise before starting a Claude session so that `go` is on the PATH:

```bash
eval "$(mise activate bash)"
```

If `go` is not found, ask the user to activate mise and restart the session.

## Local Development

Two Kind clusters are used for testing:
- **kind-cluster-a**: Runs the kube-federated-auth server
- **kind-cluster-b**: Remote cluster whose tokens are validated

Always use explicit kubectl context (`--context kind-cluster-a` or `--context kind-cluster-b`).

## Project Layout

```
cmd/
  server/main.go              # Entry point
internal/
  config/config.go            # Configuration parsing and defaults
  credentials/
    store.go                  # Credential storage, renewal, and bootstrap logic
  handler/
    tokenreview.go            # POST /apis/authentication.k8s.io/v1/tokenreviews
    clusters.go               # GET /clusters endpoint
    health.go                 # GET /health endpoint
  oidc/verifier.go            # OIDC/JWKS token verification
  server/server.go            # HTTP server setup and routing
  middleware/                 # Recovery and logging middleware
  cache/cache.go              # Generic cache
k8s/
  cluster-a/                  # Helm chart for main cluster (runs server)
  cluster-b/                  # Helm chart for remote cluster (ServiceAccount only)
test/
  e2e/                        # bats integration tests
  perf/                       # k6 load tests
config/clusters.example.yaml  # Example configuration
scripts/                      # Setup and build scripts
docs/
  DESIGN_V2.MD                # V2 architecture design document
```

## Releasing

CI handles the full release pipeline — never create GitHub releases manually.

1. Tag the commit on main: `git tag v<major>.<minor>.<patch>`
2. Push the tag: `git push origin v<major>.<minor>.<patch>`
3. CI runs test, build, then publish (pushes image to `ghcr.io/rophy/kube-federated-auth` and creates the GitHub release)

Follow [semver](https://semver.org/): bump minor for new features, patch for fixes.

## Conventions

- Commit format: `<type>: <short description>` (feat, fix, refactor, chore, docs, build, test)
- No AI attribution in commits
