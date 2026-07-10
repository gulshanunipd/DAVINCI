# Dockerfile for DAVINCI Attestation Manager
FROM rust:1.70 as builder

WORKDIR /usr/src/attestation-manager

# Copy manifests
COPY ./Cargo.toml ./Cargo.toml

# Copy source code
COPY ./src ./src

# Build the application
RUN cargo build --release

# Production image
FROM debian:bullseye-slim

# Install OpenSSL libraries
RUN apt-get update && apt-get install -y openssl libssl-dev && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/attestation-manager/target/release/attestation-manager ./attestation-manager

# Expose port
EXPOSE 3030

# Run the application
CMD ["./attestation-manager"]