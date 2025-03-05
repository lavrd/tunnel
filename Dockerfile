FROM rust:1.85-alpine3.21 AS build_tunnel
RUN apk add musl-dev
WORKDIR /tunnel
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock
COPY build.rs ./build.rs
COPY src ./src
ARG crypto
RUN if [[ -z "$crypto" ]] ; then cargo build --release ; else cargo build --release --features "crypto" ; fi


FROM golang:1.24.1-alpine3.21 AS build_dns_http_proxy
WORKDIR /dns_http_proxy
COPY dns_http_proxy/go.mod ./go.mod
COPY dns_http_proxy/main.go ./main.go
RUN go build -o dns_http_proxy


FROM alpine:3.21
# We install:
#   iproute2 - to use "ip"
#   bind-tools - to use "dig"
#   iptables - to use "iptables"
RUN apk add iproute2 bind-tools iptables
COPY --from=build_tunnel /tunnel/target/release/tunnel /tunnel
COPY --from=build_dns_http_proxy /dns_http_proxy/dns_http_proxy /dns_http_proxy
COPY scripts/run_tun_docker.sh /run_tun_docker.sh
ENTRYPOINT []
