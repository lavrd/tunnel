format:
	cargo fmt

lint: format
	cargo clippy --tests --workspace --all-targets --all-features -- -D warnings

build_macos:
	@cargo build
	@cargo-bundle bundle
	@codesign --force --sign app-signer -o runtime \
		--entitlements macos_bundle/com.example.simple.tunnel.xcent \
		--timestamp\=none --generate-entitlement-der \
		target/debug/bundle/osx/tunnel.app
