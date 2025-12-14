FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /kube-federated-auth ./cmd/server

FROM alpine:3.20

RUN apk --no-cache add ca-certificates bash tini curl

COPY --from=builder /kube-federated-auth /usr/local/bin/kube-federated-auth

EXPOSE 8080

ENTRYPOINT ["/sbin/tini", "--"]

CMD ["kube-federated-auth"]
