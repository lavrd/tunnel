use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD as B64_STANDARD, Engine};
use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{SecretKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use crate::linux::Interface;

const MTU: usize = 1500;

const NONCE_LENGTH: usize = 12;

pub(crate) fn run_tunnel(
    tun_iface_name: String,
    tun_iface_ip: String,
    udp_server_ip: String,
    upd_server_port: u16,
    b64_tunnel_private_key: String,
    b64_client_public_key: String,
) -> std::io::Result<()> {
    let client_addr = SocketAddr::from_str(&format!("{}:{}", udp_server_ip, upd_server_port))
        .map_err(map_io_err)?;
    let client_addr = Arc::new(RwLock::new(client_addr));

    let mut raw_tunnel_private_key = [0; SECRET_KEY_LENGTH];
    B64_STANDARD
        .decode_slice(b64_tunnel_private_key, &mut raw_tunnel_private_key)
        .map_err(map_io_err)?;
    let tunnel_private_key = ed25519_to_x25519_private_key(&raw_tunnel_private_key);

    let mut raw_client_public_key = [0; PUBLIC_KEY_LENGTH];
    B64_STANDARD
        .decode_slice(b64_client_public_key, &mut raw_client_public_key)
        .map_err(map_io_err)?;
    let client_public_key = ed25519_to_x25519_public_key(raw_client_public_key)?;

    let shared_secret: SharedSecret = tunnel_private_key.diffie_hellman(&client_public_key);
    let cipher = Arc::new(ChaCha20Poly1305::new(Key::from_slice(shared_secret.as_bytes())));

    eprintln!("Starting TUN device with '{}' name and '{}' IP", tun_iface_name, tun_iface_ip);

    let stop_signal: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stop_signal.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, stop_signal.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGQUIT, stop_signal.clone())?;

    start_tunnel(tun_iface_name, tun_iface_ip, upd_server_port, client_addr, cipher, stop_signal)
}

pub(crate) fn parse_ipv4(ipv4: &str) -> std::io::Result<(Ipv4Addr, Ipv4Addr)> {
    let (addr, prefix) = ipv4.split_once('/').ok_or(new_io_err("failed to split ipv4 address"))?;
    let addr: Ipv4Addr = addr.parse().map_err(map_io_err)?;
    let prefix: u8 = prefix.parse().map_err(map_io_err)?;
    if prefix > 32 {
        return Err(new_io_err("prefix is too big"));
    }
    let mut netmask: u32 = 0;
    for i in 0..prefix {
        netmask |= 1 << (31 - i);
    }
    let netmask = Ipv4Addr::from(netmask);
    Ok((addr, netmask))
}

fn start_tunnel(
    name: String,
    ip: String,
    udp_server_port: u16,
    client_addr: Arc<RwLock<SocketAddr>>,
    cipher: Arc<ChaCha20Poly1305>,
    stop_signal: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let iface = Interface::new(name, ip, MTU)?;
    let tun_fd = iface.into_tun_fd();

    let udp_socket = UdpSocket::bind(format!("0.0.0.0:{udp_server_port}"))?;
    udp_socket.set_write_timeout(Some(Duration::from_millis(500)))?;
    udp_socket.set_read_timeout(Some(Duration::from_millis(500)))?;

    start_processes(tun_fd, udp_socket, client_addr, cipher, stop_signal)
}

fn start_processes(
    tun_fd: File,
    udp_socket: UdpSocket,
    client_addr: Arc<RwLock<SocketAddr>>,
    cipher: Arc<ChaCha20Poly1305>,
    stop_signal: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let tun_fd_ = tun_fd.try_clone()?;
    let udp_socket_ = udp_socket.try_clone()?;
    let client_addr_ = client_addr.clone();
    let cipher_ = cipher.clone();
    let stop_signal_ = stop_signal.clone();
    let th: JoinHandle<()> = thread::spawn(move || {
        run_process(tun_fd_, udp_socket_, client_addr_, cipher_, stop_signal_, tun_process)
    });
    run_process(tun_fd, udp_socket, client_addr, cipher, stop_signal, rpc_process);
    th.join().map_err(|_| new_io_err("failed to waiting tun process thread"))
}

fn run_process<Func>(
    tun_td: File,
    udp_socket: UdpSocket,
    client_addr: Arc<RwLock<SocketAddr>>,
    cipher: Arc<ChaCha20Poly1305>,
    stop_signal: Arc<AtomicBool>,
    process: Func,
) where
    Func: Fn(
        File,
        UdpSocket,
        Arc<RwLock<SocketAddr>>,
        Arc<ChaCha20Poly1305>,
        Arc<AtomicBool>,
    ) -> std::io::Result<()>,
{
    if let Err(e) = process(tun_td, udp_socket, client_addr, cipher, stop_signal.clone()) {
        eprintln!("Failed to run process: {e}")
    }
    stop_signal.store(true, Ordering::Relaxed);
}

fn tun_process(
    mut tun_fd: File,
    udp_socket: UdpSocket,
    client_addr: Arc<RwLock<SocketAddr>>,
    cipher: Arc<ChaCha20Poly1305>,
    stop_signal: Arc<AtomicBool>,
) -> std::io::Result<()> {
    loop {
        if stop_signal.load(Ordering::Relaxed) {
            eprintln!("Stop signal received for TUN process");
            return Ok(());
        }
        let mut buffer = [0; MTU];
        match tun_fd.read(&mut buffer) {
            Ok(n) => {
                let buffer = &buffer[..n];
                eprintln!("Received packet from TUN: {:?}", buffer);
                let ciphertext = encrypt(buffer, &cipher)?;
                udp_socket.send_to(&ciphertext, *client_addr.read().map_err(map_io_err)?)?;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

fn rpc_process(
    mut tun_fd: File,
    udp_socket: UdpSocket,
    client_addr: Arc<RwLock<SocketAddr>>,
    cipher: Arc<ChaCha20Poly1305>,
    stop_signal: Arc<AtomicBool>,
) -> std::io::Result<()> {
    loop {
        if stop_signal.load(Ordering::Relaxed) {
            eprintln!("Stop signal received for RPC process");
            return Ok(());
        }
        let mut buffer = [0; MTU];
        match udp_socket.recv_from(&mut buffer) {
            Ok((n, addr)) => {
                if client_addr.read().map_err(map_io_err)?.clone().ne(&addr) {
                    eprintln!("Connected new client {addr}");
                    *client_addr.write().map_err(map_io_err)? = addr;
                }
                let buffer = &buffer[..n];
                let plaintext = decrypt(buffer, n, &cipher)?;
                eprintln!("Received packet from RPC: {:?}", plaintext);
                let _ = tun_fd.write(&plaintext)?;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == ErrorKind::ConnectionRefused => continue,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn encrypt(data: &[u8], cipher: &ChaCha20Poly1305) -> std::io::Result<Vec<u8>> {
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut ciphertext = cipher.encrypt(&nonce, data).map_err(map_io_err)?;
    ciphertext.extend(nonce);
    Ok(ciphertext)
}

fn decrypt(data: &[u8], n: usize, cipher: &ChaCha20Poly1305) -> std::io::Result<Vec<u8>> {
    let nonce = Nonce::from_slice(&data[n - NONCE_LENGTH..]);
    cipher.decrypt(nonce, &data[..n - NONCE_LENGTH]).map_err(map_io_err)
}

fn ed25519_to_x25519_private_key(other: &SecretKey) -> StaticSecret {
    // https://github.com/dalek-cryptography/x25519-dalek/issues/67
    let hash = Sha512::digest(other.as_slice());
    let mut output = [0; SECRET_KEY_LENGTH];
    output.copy_from_slice(&hash[..SECRET_KEY_LENGTH]);
    StaticSecret::from(output)
}

fn ed25519_to_x25519_public_key(other: [u8; PUBLIC_KEY_LENGTH]) -> std::io::Result<PublicKey> {
    // https://github.com/dalek-cryptography/x25519-dalek/issues/53
    Ok(curve25519_dalek::edwards::CompressedEdwardsY(other)
        .decompress()
        .ok_or(new_io_err("failed to decompress public key"))?
        .to_montgomery()
        .to_bytes()
        .into())
}

fn map_io_err<T: ToString>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string().as_str())
}

fn new_io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
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
