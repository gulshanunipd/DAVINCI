# Dockerfile for DAVINCI Attestation Manager
FROM rust:1-bookworm AS builder

WORKDIR /usr/src/attestation-manager

# Copy manifests
COPY ./Cargo.toml ./Cargo.toml

# Copy source code
COPY ./src ./src

# Build the application
RUN cargo build --release

# Production image
FROM debian:bookworm-slim

# Install OpenSSL libraries
RUN apt-get update && apt-get install -y openssl ca-certificates && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/attestation-manager/target/release/attestation-manager ./attestation-manager

# Expose port
EXPOSE 3030

# Run the application
CMD ["./attestation-manager"]