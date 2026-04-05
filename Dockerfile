# Multi-stage build for smaller final image
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application with optimizations
ARG TARGETARCH
ARG BUILD_VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -extldflags '-static' -X main.BuildVersion=${BUILD_VERSION}" \
    -a -installsuffix cgo \
    -o mcp-front ./cmd/mcp-front

FROM us-central1-docker.pkg.dev/database-toolbox/toolbox/toolbox:0.27.0 AS toolbox

# Final stage - use alpine for Docker CLI and tools
FROM alpine:latest

# Install runtime dependencies; gcompat provides glibc shim for toolbox binary
RUN apk --no-cache add ca-certificates docker-cli wget gcompat

# Create non-root user
RUN addgroup -g 1001 -S mcp && \
    adduser -S -D -H -u 1001 -h /app -s /sbin/nologin -G mcp -g mcp mcp

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/mcp-front .

# Copy genai-toolbox binary
COPY --from=toolbox /toolbox ./toolbox

# Change ownership
RUN chown -R mcp:mcp /app

# Use non-root user
USER mcp

# Expose port
EXPOSE 8080

# Health check using existing /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Copy Vori config
COPY vori/config.json ./config.json

# Run the application
CMD ["./mcp-front", "-config", "config.json"]
