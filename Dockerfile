FROM rust:1.79-alpine3.20 as build
RUN apk add musl-dev
WORKDIR /tunnel
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock
COPY build.rs ./build.rs
COPY src ./src
RUN cargo build --release


FROM alpine:3.20
COPY --from=build /tunnel/target/release/tunnel /tunnel
ENTRYPOINT ["/tunnel"]
