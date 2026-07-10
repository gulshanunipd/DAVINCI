# Multi-stage build for PCE Service
FROM rust:latest as builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml ./
COPY src ./src
COPY migrations ./migrations

# Build dependencies first (cached layer)
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/pce-service /app/pce-service
COPY --from=builder /app/migrations /app/migrations

# Copy policies
COPY policies /app/policies

# Expose PCE port
EXPOSE 3032

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3032/health || exit 1

# Run as non-root user
RUN useradd -m -u 1000 pce && chown -R pce:pce /app
USER pce

ENV RUST_LOG=info
ENV DATABASE_URL=postgres://pce:pce_password@pce-db:5432/pce

CMD ["./pce-service"]
