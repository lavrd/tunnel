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

run_docker_server:
	docker run --rm -it \
		--name simple-tunnel-server \
		--cap-add=NET_ADMIN \
		--device /dev/net/tun \
		-e TUNNEL_PRIVATE_KEY=RFLMRBysWs2qoDMM70xF87mPTrpTxLNTZwQwIWsIw8o= \
		-e CLIENT_PUBLIC_KEY=O+0h1KDgpw6vxQY1GUFfHhyScNpjd7EuebQvUK5L8dM= \
		-e SERVER=1 \
		--entrypoint="./run_tun_docker.sh" \
		simple-tunnel

run_docker_client:
	docker run --rm -it \
		--name simple-tunnel-client \
		--cap-add=NET_ADMIN \
		--device /dev/net/tun \
		-p 8888:8888 \
		-e TUNNEL_PRIVATE_KEY=6zZqJBS0o2/3pIRP6S659ZPr06RiAsCBKG15xHcb1OE= \
		-e CLIENT_PUBLIC_KEY=bB438yE82JeVSg3GNuinl/Sbi7Da188qjoCflkpbG9w= \
		-e CLIENT=1 \
		-e SERVER_DOCKER_IP=$(shell ./get_simple_tunnel_server_ip.sh) \
		--entrypoint=./run_tun_docker.sh \
		simple-tunnel
