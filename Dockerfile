FROM rust:1.80-alpine3.20 AS build_tunnel
RUN apk add musl-dev
WORKDIR /tunnel
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock
COPY build.rs ./build.rs
COPY src ./src
ARG crypto
RUN if [[ -z "$crypto" ]] ; then cargo build --release ; else cargo build --release --features "crypto" ; fi


FROM golang:1.22.5-alpine3.20 AS build_dns_server
WORKDIR /dns_server
COPY dns_server/go.mod ./go.mod
COPY dns_server/main.go ./main.go
RUN go build -o dns_server


FROM alpine:3.20
# We install:
#   iproute2 - to use "ip"
#   bind-tools - to use "dig"
#   iptables - to use "iptables"
RUN apk add iproute2 bind-tools iptables
COPY --from=build_tunnel /tunnel/target/release/tunnel /tunnel
COPY --from=build_dns_server /dns_server/dns_server /dns_server
COPY scripts/run_tun_docker.sh /run_tun_docker.sh
ENTRYPOINT []
