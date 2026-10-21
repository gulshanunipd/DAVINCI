# Makefile for DAVINCI Prototype

PLATFORM_IMAGE ?= davinci-platform
PLATFORM_STATE ?= davinci-platform-state

# Default target
.PHONY: all
all: build

# Generate the Attestation Manager ECDSA-P256 key pair. Run once before use.
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

# Build the attested platform image: swtpm (TPM 2.0) + TF-A/OP-TEE/Linux on
# QEMU + the MRAL collectors. First build takes ~20 min (kernel, firmware).
.PHONY: platform-image
platform-image:
	DOCKER_BUILDKIT=1 docker build -t $(PLATFORM_IMAGE) mral-adapters

# Run the attested platform. Publishes the TPM manufacturer CA to keys/rot/.
.PHONY: platform
platform: platform-image
	mkdir -p keys/rot
	-docker rm -f davinci-platform >/dev/null 2>&1
	docker run -d --name davinci-platform -p 4000:4000 -p 4010:4010 -p 4020:4020 \
	  -v $(PLATFORM_STATE):/var/lib/davinci -v "$(CURDIR)/keys/rot":/trust $(PLATFORM_IMAGE)
	@echo "Platform booting (TPM collector :4010, OP-TEE collector :4020, controller :4000)"

.PHONY: platform-stop
platform-stop:
	-docker rm -f davinci-platform

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

# Run everything with Docker Compose
.PHONY: docker-run
docker-run: keys
	@echo "Starting services with Docker Compose..."
	docker-compose up --build

# Stop Docker services
.PHONY: docker-stop
docker-stop:
	@echo "Stopping Docker services..."
	docker-compose down

# Enroll the RoTs and record reference values (run once the stack is up)
.PHONY: provision
provision:
	cd demo && python3 provision.py

# Run demo
.PHONY: demo
demo:
	@echo "Running DAVINCI demo..."
	cd demo && python3 demo_scenario.py

# Run one scenario: make demo-trust SCENARIO=tampered-ta
SCENARIO ?= good
.PHONY: demo-trust
demo-trust:
	cd demo && python3 demo_trusted_vs_untrusted.py $(SCENARIO)

# Run all trusted/untrusted scenarios side by side
.PHONY: demo-compare
demo-compare:
	@echo "Running trusted vs untrusted comparison demo..."
	cd demo && python3 demo_comparison.py

# Unit tests of the Rust services
.PHONY: test
test:
	@echo "Running tests for Attestation Manager..."
	cd attestation-manager && cargo test
	@echo "Running tests for Verifier..."
	cd verifier && cargo test
	@echo "Running tests for Privacy Control Engine..."
	cd pce-service && cargo test --lib   # tests/test_persistence.rs needs DATABASE_URL (Postgres)

# End-to-end test against the running platform and services
.PHONY: test-e2e
test-e2e:
	./demo/test_integration.sh

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	cd attestation-manager && cargo clean
	cd verifier && cargo clean
	cd pce-service && cargo clean

# Help
.PHONY: help
help:
	@echo "DAVINCI Prototype Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  build                - Generate AM key, build the three Rust services"
	@echo "  platform-image       - Build the attested platform image (TPM + OP-TEE)"
	@echo "  platform             - Run the attested platform container"
	@echo "  platform-stop        - Stop the platform container"
	@echo "  run-pce              - Run Privacy Control Engine (:3032)"
	@echo "  run-attestation-manager - Run Attestation Manager (:3030)"
	@echo "  run-verifier         - Run Verifier (:3031)"
	@echo "  docker-run           - Run platform + services with Docker Compose"
	@echo "  docker-stop          - Stop Docker services"
	@echo "  provision            - Enroll RoTs and record reference values"
	@echo "  demo                 - Run one end-to-end attestation round"
	@echo "  demo-trust           - Run one scenario (SCENARIO=good|tampered-kernel|tampered-ta|replay)"
	@echo "  demo-compare         - Run all scenarios side by side"
	@echo "  test                 - Unit tests of the Rust services"
	@echo "  test-e2e             - End-to-end test against the running stack"
	@echo "  clean                - Clean build artifacts"
	@echo "  help                 - Show this help message"
