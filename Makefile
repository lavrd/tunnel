format:
	cargo fmt

lint: format
	cargo clippy --tests --workspace --all-targets --all-features -- -D warnings

build:
	@cargo build

build_docker:
	docker build -t simple-tunnel -f Dockerfile .

build_macos_notifications:
	@cargo-bundle bundle --features notifications
	@codesign --force --sign app-signer -o runtime \
		--entitlements macos_bundle/com.example.simple.tunnel.xcent \
		--timestamp\=none --generate-entitlement-der \
		target/debug/bundle/osx/tunnel.app
