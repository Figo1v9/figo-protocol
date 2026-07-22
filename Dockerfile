# Multi-stage build Dockerfile for FGXP (FigoX Protocol)

# Stage 1: Build
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy dependency files and download
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binaries
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/bin/fgxp-server ./cmd/fgxp-server/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /app/bin/fgxp-client ./cmd/fgxp-client/main.go

# Stage 2: Final minimal image
FROM alpine:3.20

# Install ca-certificates for TLS verification
RUN apk add --no-cache ca-certificates

WORKDIR /root/

# Copy binaries from builder
COPY --from=builder /app/bin/fgxp-server /usr/local/bin/fgxp-server
COPY --from=builder /app/bin/fgxp-client /usr/local/bin/fgxp-client

# Copy default configurations
COPY --from=builder /app/configs/server.example.yaml /etc/fgxp/server.yaml
COPY --from=builder /app/configs/client.example.yaml /etc/fgxp/client.yaml

# Expose default protocol port
EXPOSE 443 443/udp

# Run server by default
ENTRYPOINT ["/usr/local/bin/fgxp-server"]
CMD ["--config", "/etc/fgxp/server.yaml"]
