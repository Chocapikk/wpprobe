# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o wpprobe ./main.go

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/wpprobe /usr/local/bin/wpprobe

# Create directories for data and config
RUN mkdir -p /data /config

# Set volumes for easy file mounting
VOLUME ["/data", "/config"]

# Set working directory to /data for easy file access
WORKDIR /data

# Set config directory environment variable
ENV XDG_CONFIG_HOME=/config

ENTRYPOINT ["wpprobe"]
