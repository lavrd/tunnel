format:
	cargo fmt

lint: format
	cargo clippy --tests --workspace --all-targets --all-features -- -D warnings
