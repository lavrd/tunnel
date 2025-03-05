use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    str::FromStr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use log::{debug, error, info};

#[cfg(feature = "crypto")]
use crate::crypto;
use crate::{linux::Device, map_io_err, new_io_err};

const MTU: usize = 1500;

trait Process {
    fn run(
        &self,
        tun_fd: File,
        udp_socket: UdpSocket,
        client_addr: Arc<RwLock<SocketAddr>>,
        stop_signal: Arc<AtomicBool>,
    ) -> std::io::Result<()>;
}

pub(crate) fn run_tunnel(
    tun_device_name: String,
    tun_device_ip: String,
    udp_server_ip: String,
    upd_server_port: u16,
    #[cfg(feature = "crypto")] b64_tunnel_private_key: String,
    #[cfg(feature = "crypto")] b64_client_public_key: String,
) -> std::io::Result<()> {
    let client_addr = SocketAddr::from_str(&format!("{}:{}", udp_server_ip, upd_server_port))
        .map_err(map_io_err)?;
    let client_addr = Arc::new(RwLock::new(client_addr));

    info!("Starting TUN device with '{}' name and '{}' IP", tun_device_name, tun_device_ip);

    let stop_signal: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stop_signal.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, stop_signal.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGQUIT, stop_signal.clone())?;

    init_tunnel(
        client_addr,
        tun_device_name,
        tun_device_ip,
        upd_server_port,
        #[cfg(feature = "crypto")]
        b64_tunnel_private_key,
        #[cfg(feature = "crypto")]
        b64_client_public_key,
        stop_signal,
    )
}

pub(crate) fn parse_ipv4(ipv4: &str) -> std::io::Result<(Ipv4Addr, Ipv4Addr)> {
    let (addr, prefix) = ipv4.split_once('/').ok_or(new_io_err("failed to split ipv4 address"))?;
    let addr: Ipv4Addr = addr.parse().map_err(map_io_err)?;
    let prefix: u8 = prefix.parse().map_err(map_io_err)?;
    if prefix > 32 {
        return Err(new_io_err("prefix is too big"));
    }
    // Example:
    // /24
    // i = 0 -> 1 << (31 - 0) = 10000000 00000000 00000000 00000000
    // i = 1 -> 1 << (31 - 1) = 01000000 00000000 00000000 00000000
    // ...
    // i = 23 -> 1 << (31 - 23) 00000000 00000000 00000001 00000000
    let mut netmask: u32 = 0;
    for i in 0..prefix {
        netmask |= 1 << (31 - i);
    }
    // 11111111 11111111 11111111 00000000 = 255.255.255.0
    let netmask = Ipv4Addr::from(netmask);
    Ok((addr, netmask))
}

struct Tunnel {
    #[cfg(feature = "crypto")]
    cipher: Arc<crypto::cipher::Cipher>,
}

impl Tunnel {
    fn start_tunnel(
        self,
        name: String,
        ip: String,
        udp_server_port: u16,
        client_addr: Arc<RwLock<SocketAddr>>,
        stop_signal: Arc<AtomicBool>,
    ) -> std::io::Result<()> {
        let device = Device::new(name, ip, MTU)?;
        let tun_fd = device.into_tun_fd();

        let udp_socket = UdpSocket::bind(format!("0.0.0.0:{udp_server_port}"))?;
        udp_socket.set_write_timeout(Some(Duration::from_millis(500)))?;
        udp_socket.set_read_timeout(Some(Duration::from_millis(500)))?;

        self.start_processes(tun_fd, udp_socket, client_addr, stop_signal)
    }

    fn start_processes(
        self,
        tun_fd: File,
        udp_socket: UdpSocket,
        client_addr: Arc<RwLock<SocketAddr>>,
        stop_signal: Arc<AtomicBool>,
    ) -> std::io::Result<()> {
        let tun_fd_ = tun_fd.try_clone()?;
        let udp_socket_ = udp_socket.try_clone()?;
        let client_addr_ = client_addr.clone();
        #[cfg(feature = "crypto")]
        let cipher_ = self.cipher.clone();
        let stop_signal_ = stop_signal.clone();
        let th: JoinHandle<()> = thread::spawn(move || {
            run_process(
                tun_fd_,
                udp_socket_,
                client_addr_,
                stop_signal_,
                TunProcess {
                    #[cfg(feature = "crypto")]
                    cipher: cipher_,
                },
            )
        });
        run_process(
            tun_fd,
            udp_socket,
            client_addr,
            stop_signal,
            RpcProcess {
                #[cfg(feature = "crypto")]
                cipher: self.cipher,
            },
        );
        th.join().map_err(|_| new_io_err("failed to waiting tun process thread"))
    }
}

#[cfg(feature = "crypto")]
fn init_tunnel(
    client_addr: Arc<RwLock<SocketAddr>>,
    tun_device_name: String,
    tun_device_ip: String,
    upd_server_port: u16,
    #[cfg(feature = "crypto")] b64_tunnel_private_key: String,
    #[cfg(feature = "crypto")] b64_client_public_key: String,
    stop_signal: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let cipher = crypto::cipher::init_cipher(b64_tunnel_private_key, b64_client_public_key)?;
    Tunnel {
        cipher: Arc::new(cipher),
    }
    .start_tunnel(tun_device_name, tun_device_ip, upd_server_port, client_addr, stop_signal)
}

#[cfg(not(feature = "crypto"))]
fn init_tunnel(
    client_addr: Arc<RwLock<SocketAddr>>,
    tun_device_name: String,
    tun_device_ip: String,
    upd_server_port: u16,
    stop_signal: Arc<AtomicBool>,
) -> std::io::Result<()> {
    Tunnel {}.start_tunnel(
        tun_device_name,
        tun_device_ip,
        upd_server_port,
        client_addr,
        stop_signal,
    )
}

fn run_process<P>(
    tun_td: File,
    udp_socket: UdpSocket,
    client_addr: Arc<RwLock<SocketAddr>>,
    stop_signal: Arc<AtomicBool>,
    process: P,
) where
    P: Process,
{
    if let Err(e) = process.run(tun_td, udp_socket, client_addr, stop_signal.clone()) {
        error!("Failed to run process: {e}")
    }
}

struct TunProcess {
    #[cfg(feature = "crypto")]
    cipher: Arc<crypto::cipher::Cipher>,
}

impl Process for TunProcess {
    fn run(
        &self,
        mut tun_fd: File,
        udp_socket: UdpSocket,
        client_addr: Arc<RwLock<SocketAddr>>,
        stop_signal: Arc<AtomicBool>,
    ) -> std::io::Result<()> {
        loop {
            if stop_signal.load(Ordering::Relaxed) {
                debug!("Stop signal received for TUN process");
                return Ok(());
            }
            let mut buffer = [0; MTU];
            match tun_fd.read(&mut buffer) {
                Ok(n) => {
                    let buffer = &buffer[..n];
                    debug!("Received packet from TUN: {:?}", buffer);
                    #[cfg(feature = "crypto")]
                    let buffer = &self.cipher.encrypt(buffer)?;
                    udp_socket.send_to(buffer, *client_addr.read().map_err(map_io_err)?)?;
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

struct RpcProcess {
    #[cfg(feature = "crypto")]
    cipher: Arc<crypto::cipher::Cipher>,
}

impl Process for RpcProcess {
    fn run(
        &self,
        mut tun_fd: File,
        udp_socket: UdpSocket,
        client_addr: Arc<RwLock<SocketAddr>>,
        stop_signal: Arc<AtomicBool>,
    ) -> std::io::Result<()> {
        loop {
            if stop_signal.load(Ordering::Relaxed) {
                debug!("Stop signal received for RPC process");
                return Ok(());
            }
            let mut buffer = [0; MTU];
            match udp_socket.recv_from(&mut buffer) {
                Ok((n, addr)) => {
                    if client_addr.read().map_err(map_io_err)?.clone().ne(&addr) {
                        info!("Connected new client {addr}");
                        *client_addr.write().map_err(map_io_err)? = addr;
                    }
                    let buffer = &buffer[..n];
                    #[cfg(feature = "crypto")]
                    let buffer = &self.cipher.decrypt(buffer, n)?;
                    debug!("Received packet from RPC: {:?}", buffer);
                    let _ = tun_fd.write(buffer)?;
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(ref e) if e.kind() == ErrorKind::ConnectionRefused => continue,
                Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ipnet::Ipv4Net;

    use crate::tunnel::parse_ipv4;

    #[test]
    fn test_ipv4net_parsing() {
        let test_cases: Vec<&str> = vec![
            "10.0.0.1/24",
            "10.0.0.1/32",
            "10.0.0.1/0",
            "10.0.0.1/0",
            "192.168.0.1/12",
        ];
        for test_case in test_cases {
            let required: Ipv4Net = test_case.parse().unwrap();
            let (addr, netmask): (Ipv4Addr, Ipv4Addr) = parse_ipv4(test_case).unwrap();
            assert_eq!(required.addr(), addr);
            assert_eq!(required.netmask(), netmask);
        }
    }
}
