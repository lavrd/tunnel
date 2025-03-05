format:
	cargo fmt

lint: format
	cargo clippy --tests --workspace --all-targets --all-features -- -D warnings

test:
	cargo test -- --nocapture

build:
	@cargo build

build_docker:
	docker build -t simple-tunnel -f Dockerfile .

build_docker_crypto:
	docker build -t simple-tunnel -f Dockerfile --build-arg crypto=1 .

build_macos_notifications:
	@cargo-bundle bundle --features notifications
	@codesign --force --sign app-signer -o runtime \
		--entitlements macos_bundle/com.example.simple.tunnel.xcent \
		--timestamp\=none --generate-entitlement-der \
		target/debug/bundle/osx/tunnel.app

run_dns_server:
	docker run --rm -it \
		--name dns-server \
		-p 12400:53/udp \
		-v "${PWD}/coredns/Corefile:/Corefile" \
		-v "${PWD}/coredns/core.db:/core.db" \
		coredns/coredns -conf /Corefile

run_docker_server:
	docker run --rm -it \
		--name simple-tunnel-server \
		--cap-add=NET_ADMIN \
		--privileged \
		--device /dev/net/tun \
		--memory=0.5g \
		--memory-swap=0.5g \
		--cpus=1 \
		-e RUST_LOG=$(log_level) \
		-e SERVER=1 \
		--entrypoint="./run_tun_docker.sh" \
		simple-tunnel

run_docker_server_crypto:
	docker run --rm -it \
		--name simple-tunnel-server \
		--cap-add=NET_ADMIN \
		--device /dev/net/tun \
		--memory=0.5g \
		--memory-swap=0.5g \
		--cpus=1 \
		-e RUST_LOG=$(log_level) \
		-e TUNNEL_PRIVATE_KEY=RFLMRBysWs2qoDMM70xF87mPTrpTxLNTZwQwIWsIw8o= \
		-e CLIENT_PUBLIC_KEY=O+0h1KDgpw6vxQY1GUFfHhyScNpjd7EuebQvUK5L8dM= \
		-e SERVER=1 \
		--entrypoint="./run_tun_docker.sh" \
		simple-tunnel

run_docker_client:
	docker run --rm -it \
		--name simple-tunnel-client \
		--cap-add=NET_ADMIN \
		--privileged \
		--device /dev/net/tun \
		--memory=0.5g \
		--memory-swap=0.5g \
		--cpus=1 \
		-p 8888:8888 \
		-e RUST_LOG=$(log_level) \
		-e CLIENT=1 \
		-e SERVER_DOCKER_IP=$(shell ./scripts/get_simple_tunnel_server_ip.sh) \
		-e DNS_SERVER_IP=$(shell ./scripts/get_dns_server_ip.sh) \
		-e ROUTING=$(routing) \
		--entrypoint="./run_tun_docker.sh" \
		simple-tunnel

run_docker_client_crypto:
	docker run --rm -it \
		--name simple-tunnel-client \
		--cap-add=NET_ADMIN \
		--device /dev/net/tun \
		--memory=0.5g \
		--memory-swap=0.5g \
		--cpus=1 \
		-p 8888:8888 \
		-e RUST_LOG=$(log_level) \
		-e TUNNEL_PRIVATE_KEY=6zZqJBS0o2/3pIRP6S659ZPr06RiAsCBKG15xHcb1OE= \
		-e CLIENT_PUBLIC_KEY=bB438yE82JeVSg3GNuinl/Sbi7Da188qjoCflkpbG9w= \
		-e CLIENT=1 \
		-e SERVER_DOCKER_IP=$(shell ./acripts/get_simple_tunnel_server_ip.sh) \
		-e DNS_SERVER_IP=$(shell ./scripts/get_dns_server_ip.sh) \
		-e ROUTING=$(routing) \
		--entrypoint="./run_tun_docker.sh" \
		simple-tunnel

run_benchmarks:
	cd benchmarks && go run main.go run constant \
		-c 50 \
		--max-duration 60s \
		--max-iterations 10000 \
		--rate 50/s \
		$(name)

check_updates:
	cargo outdated --color always -R
