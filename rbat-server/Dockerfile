# ============================================
# Stage 1: Build the Rust binary
# ============================================
FROM rust:1.85 AS builder

WORKDIR /app

# Install protobuf compiler for tonic-build (gRPC)
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Copy workspace configuration and source directories
COPY Cargo.toml Cargo.lock ./
COPY proto ./proto
COPY rbat-server ./rbat-server
COPY rbat-core ./rbat-core

# Build rbat-server in release mode
# Use cache mounts for cargo registry and target directory to speed up rebuilds
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --package rbat-server && \
    cp target/release/rbat-server /app/rbat-server

# ============================================
# Stage 2: Runtime Environment
# ============================================
FROM debian:bookworm-slim AS runner

WORKDIR /app

# Copy the compiled binary from builder
COPY --from=builder /app/rbat-server /usr/local/bin/rbat-server

# Set production environment variables
ENV HOST=0.0.0.0
ENV PORT=8080

# Create sandbox directory mount
RUN mkdir -p /tmp/sandbox && chmod 1777 /tmp/sandbox

# Expose server port
EXPOSE 8080

# Run as non-root user for security best practices
USER nobody

# Start the server
ENTRYPOINT ["/usr/local/bin/rbat-server"]
