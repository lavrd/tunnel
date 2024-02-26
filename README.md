# Tunnel

Simple network tunnel as an example.

## Usage

### Client

```shell
cargo build ; sudo target/debug/tunnel tun0 10.0.0.1/24 client
sudo ip route add 1.1.1.1/32 dev tun0
ping 1.1.1.1 -c 1
```

### Server

```shell
iptables-save
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

sysctl net.ipv4.ip_forward
sudo sysctl -w net.ipv4.ip_forward=1

cargo build ; sudo target/debug/tunnel tun0 10.0.0.2/24 server
```

Trace IP packets: `tcpdump -v -i tun0 proto \\icmp`.
