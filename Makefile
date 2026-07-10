# Makefile for DAVINCI Prototype

# Default target
.PHONY: all
all: build

# Generate ECDSA-P256 keys (AM + per-RoT trusted material). Run once before use.
.PHONY: keys
keys:
	@echo "Generating DAVINCI keys..."
	./keys/gen-keys.sh

# Build all Rust services
.PHONY: build
build: keys
	@echo "Building Privacy Control Engine..."
	cd pce-service && cargo build
	@echo "Building Attestation Manager..."
	cd attestation-manager && cargo build
	@echo "Building Verifier..."
	cd verifier && cargo build
	@echo "Build complete!"

# Run all services (recommended: run each target in its own terminal)
.PHONY: run
run: run-pce run-attestation-manager run-verifier

# Run Privacy Control Engine (start FIRST; run from its dir so it finds policies/)
.PHONY: run-pce
run-pce:
	@echo "Starting Privacy Control Engine on port 3032..."
	cd pce-service && cargo run

# Run Attestation Manager
.PHONY: run-attestation-manager
run-attestation-manager:
	@echo "Starting Attestation Manager on port 3030..."
	cd attestation-manager && cargo run

# Run Verifier
.PHONY: run-verifier
run-verifier:
	@echo "Starting Verifier on port 3031..."
	cd verifier && cargo run

# Run with Docker
.PHONY: docker-run
docker-run:
	@echo "Starting services with Docker Compose..."
	docker-compose up --build

# Stop Docker services
.PHONY: docker-stop
docker-stop:
	@echo "Stopping Docker services..."
	docker-compose down

# Run demo
.PHONY: demo
demo:
	@echo "Running DAVINCI demo..."
	cd demo && python3 demo_scenario.py

# Run boot attestation demo
.PHONY: demo-boot
demo-boot:
	@echo "Running boot attestation demo..."
	cd demo && chmod +x boot_attestation.sh && ./boot_attestation.sh

# Run runtime attestation demo
.PHONY: demo-runtime
demo-runtime:
	@echo "Running runtime attestation demo..."
	cd demo && chmod +x runtime_attestation.sh && ./runtime_attestation.sh

# Run trusted vs untrusted demo
.PHONY: demo-trust
demo-trust:
	@echo "Running trusted vs untrusted demo..."
	cd demo && python3 demo_trusted_vs_untrusted.py

# Run untrusted demo
.PHONY: demo-untrusted
demo-untrusted:
	@echo "Running untrusted demo..."
	cd demo && python3 demo_trusted_vs_untrusted.py untrusted

# Run comparison demo
.PHONY: demo-compare
demo-compare:
	@echo "Running trusted vs untrusted comparison demo..."
	cd demo && python3 demo_comparison.py

# Test Rust services
.PHONY: test
test:
	@echo "Running tests for Attestation Manager..."
	cd attestation-manager && cargo test
	@echo "Running tests for Verifier..."
	cd verifier && cargo test

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	cd attestation-manager && cargo clean
	cd verifier && cargo clean

# Install Python dependencies
.PHONY: install-python-deps
install-python-deps:
	@echo "Installing Python dependencies..."
	pip install requests

# Setup development environment
.PHONY: setup
setup: install-python-deps
	@echo "Development environment setup complete!"

# Help
.PHONY: help
help:
	@echo "DAVINCI Prototype Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all                  - Build all services (default)"
	@echo "  build                - Build all Rust services"
	@echo "  run                  - Run all services"
	@echo "  run-attestation-manager - Run Attestation Manager service"
	@echo "  run-verifier         - Run Verifier service"
	@echo "  docker-run           - Run all services with Docker Compose"
	@echo "  docker-stop          - Stop Docker services"
	@echo "  demo                 - Run complete DAVINCI demo"
	@echo "  demo-boot            - Run boot attestation demo"
	@echo "  demo-runtime         - Run runtime attestation demo"
	@echo "  demo-trust           - Run trusted vs untrusted demo"
	@echo "  demo-untrusted       - Run untrusted demo"
	@echo "  demo-compare         - Run comparison demo"
	@echo "  test                 - Run tests for all services"
	@echo "  clean                - Clean build artifacts"
	@echo "  setup                - Setup development environment"
	@echo "  help                 - Show this help message"