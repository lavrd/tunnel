# Tunnel

Simple network tunnel (and how to work with Linux TUN device) as an example.

_Tunnel is working on only on Linux or inside Docker containers._

## Usage

Generate private and public keys.

```shell
cargo run -- generate
```

### Run on Linux host

#### Server

First of all you need to setup NAT routing and forwarding in the operating system.

Use `ifconfig` to find an proper interface which has an access to the global network. For example network interface can have a name `enp1s0`.

```shell
sudo iptables -t nat -A POSTROUTING -o enp1s0 -j MASQUERADE
```

To check that command was successfully executed you can use following command and find your rule.

```shell
sudo iptables-save
```

Also you need to setup ip forwarding.

```
sudo sysctl -w net.ipv4.ip_forward=1
```

Use command to check.

```
sysctl net.ipv4.ip_forward
```

You should see and output with `= 1`.

After that you can run tunnel server.


```shell
cargo build && \
  sudo target/debug/tunnel run \
  <server_private_key> <client_public_key> \
  --tun-device-ip 10.0.0.2/24
```

#### Client

```shell
# Build and run tunnel client.
cargo build && \
  sudo target/debug/tunnel run \
  <client_private_key> <server_public_key> \
  --tun-device-ip 10.0.0.3/24 --udp-server-ip <tunnel_server_public_ip>
# Route all traffic to 1.1.1.1 through client tunnel interface.
sudo ip route add 1.1.1.1/32 dev tun0
```

To check that tunnel is setup correctly you can use `ping` command: `ping 1.1.1.1 -c 1`.

It is very crucial to setup different IPs for client and server TUN devices, others packets not going correctly through tunnel.

#### Example

```shell
# Server.
cargo build && \
  sudo target/debug/tunnel run \
  nE84pUNAM0LsWx+tjJLElU9vEEi1fm5UxucRyTfTrok= /i4WwxYB7KPoFNFCiIR67KpROr6f8Y6Ht56Z2LXZOLE= \
  --tun-device-ip 10.0.0.2/24

# Client.
cargo build && \
  sudo target/debug/tunnel run \
  7y6VlMKnBWxFoCc06E2BCEaBTk9rKu8MQOwsjGcmHdw= ioABH93leNl4oiHy9k8O5NVPM7W8TEwgj9IGtycZUKM= \
  --tun-device-ip 10.0.0.3/24 --udp-server-ip 127.0.0.1
```

### Run in Docker

In order to run the tunnel (client and server) in the Docker you first need to build docker image.

```shell
# To build without encryption.
make build_docker

# To build with encryption capabilities.
make build_docker_crypto
```

After that you need to start tunnel server.

```shell
# To run without encryption and with disabled logs.
make run_docker_server log_level=off

# To run with encryption capabilities and log level is trace.
make run_docker_server_crypto log_level=trace
```

And finally you can start tunne client. To run this command [jq](https://github.com/jqlang/jq) is required to be installed.

```shell
# To run without encryption.
make run_docker_client log_level=off

# To run with encryption capabilities.
make run_docker_server_client log_level=trace
```

Wait until client HTTP server will be started.

To test that tunnel is working you can request DNS HTTP proxy server to resolve some DNS name.

```shell
curl -iX GET 'http://127.0.0.1:8888/resolve?name=cloudflare.com'
```

You can see in the client and server tunnels logs that packets were going through them before reached `1.1.1.1` DNS server.

### Troubleshooting

If you are encountering some problems and packets are not going through tunnel correctly, use `tcpdump`.

```shell
# To check only ICMP packets.
tcpdump -v -i tun0 proto \\icmp
# Check any packets for particular IP.
tcpdump -i enp1s0 dst 1.1.1.1 or src 1.1.1.1
```

## Custom DNS server

To use custom DNS server (clouddns, for example) you can run following command:

```shell
make run_dns_server
```

After that when you start docker containers for establish a tunnel it will find this server address automatically.

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

After signing key creation you need to be able to build macOS bundle after Rust binary compilation. Install [this tool](https://github.com/burtonageo/cargo-bundle) to do it automatically.

`Cargo.toml` contains `[package.metadata.bundle]` section to describe bundle metadata. Also we have some configuration in `./macos_bundle` folder.

### Build

To build you can use target from Makefile: `make build_macos_notifications`. It will be built, bundled and signed.

Then, to execute binary, use following binary: `target/debug/bundle/osx/tunnel.app/Contents/MacOS/tunnel`.

Thanks to https://shadowfacts.net/2023/rust-swift/.

## Benchmarks

Start client and server. On the client side use following command:

```shell
make run_benchmarks name=tunnel_dig
make run_benchmarks name=tunnel_go
```

### Results

| Time | RPS | Memory | Swap | CPUs |
|-|-|-|-|-|
| 1m | 50rps | 0.5g | 0.5g | 1 |

|| Avg | Min | Max |
|-|-|-|-|
| Without tunnel and without local DNS **[DQI]** | 6.4ms | 762.33ns | 541ms |
| Without tunnel but with local DNS | 4.43ms | 1.00ms | 12.84ms |
| With tunnel but without local DNS **[DQI]** | 9.97ms | 5.55ms | 98.91ms |
| With tunnel and with local DNS | 2.32ms | 1.01ms | 5.80ms |
| With encrypted tunnel and with local DNS | 2.44ms | 867.25ns | 11.00ms |
| With tunnel and with local DNS **_(dig)_** | 57.77ms | 32.84ms | 136.72ms |

**[DQI]** means benchmark depends on the quality of the Internet (ping). \
**_(dig)_** means `dig` command was used by DNS HTTP proxy server to reach DNS server.
