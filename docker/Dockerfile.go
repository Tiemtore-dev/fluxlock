# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev sqlite-dev

# Copy go mod files
COPY go-api-server/go.mod go-api-server/go.sum ./
RUN go mod download

# Copy source code
COPY go-api-server/ ./

# Build
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o server cmd/server/main.go

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates sqlite-libs

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/server .

# Copy config
COPY go-api-server/config ./config

# Create data directory
RUN mkdir -p /data

EXPOSE 8080

CMD ["./server"]
