FROM golang:1.24-alpine AS builder

ARG VERSION=dev

WORKDIR /app

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -ldflags "-X main.Version=${VERSION}" -o /kube-federated-auth ./cmd/server

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /kube-federated-auth /usr/local/bin/kube-federated-auth

EXPOSE 8080

USER 65534:65534

ENTRYPOINT ["kube-federated-auth"]
