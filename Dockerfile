FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /multi-k8s-auth ./cmd/server

FROM alpine:3.20

RUN apk --no-cache add ca-certificates bash tini curl

COPY --from=builder /multi-k8s-auth /usr/local/bin/multi-k8s-auth

EXPOSE 8080

ENTRYPOINT ["/sbin/tini", "--"]

CMD ["multi-k8s-auth"]
