.PHONY: all fmt fmt-check lint test check build release clean docker docker-multiarch

all: fmt lint test build

# Format all code
fmt:
	cargo fmt --all

# Format check (CI-friendly, fails on unformatted code)
fmt-check:
	cargo fmt --all -- --check

# Lint with clippy
lint:
	cargo clippy --workspace --all-targets -- -D warnings

# Run tests
test:
	cargo test --workspace

# Type-check without building
check:
	cargo check --workspace

# Debug build
build:
	cargo build --workspace

# Release build
release:
	cargo build --release --workspace

# Clean build artifacts
clean:
	cargo clean

# Build Docker image
docker:
	docker build -t softhsm2-pkcs11-proxy:latest .

# Build multi-arch Docker image (arm64 + amd64)
docker-multiarch:
	docker buildx build --platform linux/arm64,linux/amd64 -t softhsm2-pkcs11-proxy:latest .
