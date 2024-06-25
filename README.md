# Tunnel

Simple network tunnel as an example.

## Usage

Generate private and public keys.

```shell
cargo run -- generate
```

### Client

```shell
cargo build && sudo target/debug/tunnel run <private_key> <client_public_key> --udp-server-ip 127.0.0.1
sudo ip route add 1.1.1.1/32 dev tun0
ping 1.1.1.1 -c 1
```

### Server

```shell
iptables-save
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

sysctl net.ipv4.ip_forward
sudo sysctl -w net.ipv4.ip_forward=1

cargo build && sudo target/debug/tunnel run <private_key> <client_public_key> --tun-iface-ip 10.0.0.2/24
```

Trace IP packets: `tcpdump -v -i tun0 proto \\icmp`.

### Example

```shell
# Client.
cargo build && sudo target/debug/tunnel run 7y6VlMKnBWxFoCc06E2BCEaBTk9rKu8MQOwsjGcmHdw= ioABH93leNl4oiHy9k8O5NVPM7W8TEwgj9IGtycZUKM= --udp-server-ip 127.0.0.1

# Server.
cargo build && sudo target/debug/tunnel run nE84pUNAM0LsWx+tjJLElU9vEEi1fm5UxucRyTfTrok= /i4WwxYB7KPoFNFCiIR67KpROr6f8Y6Ht56Z2LXZOLE= --tun-iface-ip 10.0.0.2/24
```

## macOS notifications

### Signing

In order to run firmware on macOS for demo purposes it is required to sign it by self-issued certificate.

You can check [following docs](https://support.apple.com/en-gb/guide/keychain-access/kyca8916/mac) how to do it. Use name `app-signer` (you can choose any name but in that case you need to update commands below) for your certificate.

Commands to check that everything is fine:

```shell
# By following command you can check that your certificate in the list.
security find-identity -p codesigning
codesign -f -s "app-signer" <some-file> --deep
```

### Bundling

After signing key creation you need to be able to build macOS bundle after Rust binary compliation. Install [this tool](https://github.com/burtonageo/cargo-bundle) to do it automatically.

`Cargo.toml` contains `[package.metadata.bundle]` section to describe bundle metadata. Also we have some configuration in `./macos_bundle` folder.

### Build

To build you can use target from Makefile: `make build_macos`. It will be built, bundled and signed.

Then, to execute binary, use following binary: `target/debug/bundle/osx/tunnel.app/Contents/MacOS/tunnel`.
