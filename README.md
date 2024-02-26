# Tunnel

Simple network tunnel as an example.

## Usage

### Client

```shell
cargo build ; sudo target/debug/tunnel tun0 10.0.0.1/24
sudo ip route add 1.1.1.1/32 dev tun0
ping 1.1.1.1 -c 1
```
