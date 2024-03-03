use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use ipnet::Ipv4Net;

#[cfg(target_os = "linux")]
use linux::Interface;

mod ioctl;
mod linux;

const MTU: usize = 512;

const SIDE_CLIENT: &str = "client";
const SIDE_SERVER: &str = "server";

const UDP_SOCKET_PORT: u16 = 6688;

fn main() -> std::io::Result<()> {
    let name = std::env::args().nth(1).ok_or_else(|| new_io_err("failed to find arg with name"))?;
    let ip: Ipv4Net = std::env::args()
        .nth(2)
        .ok_or_else(|| new_io_err("failed to find arg with ip"))?
        .parse()
        .map_err(map_io_err)?;
    let side = std::env::args().nth(3).ok_or_else(|| new_io_err("failed to find arg with side"))?;
    let client_addr: Arc<RwLock<SocketAddr>> = if side == SIDE_CLIENT {
        Arc::new(RwLock::new(
            std::env::args()
                .nth(4)
                .ok_or_else(|| new_io_err("failed to find arg with server address"))?
                .parse()
                .map_err(map_io_err)?,
        ))
    } else {
        Arc::new(RwLock::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)))
    };
    eprintln!("Starting TUN device with '{}' name and '{}' IP", name, ip);

    let stop_signal: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stop_signal.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, stop_signal.clone())?;
    signal_hook::flag::register(signal_hook::consts::SIGQUIT, stop_signal.clone())?;

    start_process(name, ip, side, client_addr, stop_signal)
}

pub(crate) fn map_io_err<T: ToString>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string().as_str())
}

pub(crate) fn map_io_err_msg<T: ToString>(e: T, msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{}: {}", e.to_string(), msg))
}

fn start_process(
    name: String,
    ip: Ipv4Net,
    side: String,
    client_addr: Arc<RwLock<SocketAddr>>,
    stop_signal: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let iface = Interface::new(name, ip, MTU)?;
    let tun_fd = iface.into_tun_fd();

    let udp_socket = match side.as_str() {
        SIDE_CLIENT => UdpSocket::bind("0.0.0.0:0")?,
        SIDE_SERVER => UdpSocket::bind(format!("0.0.0.0:{UDP_SOCKET_PORT}"))?,
        _ => return Err(new_io_err("unknown side to create new udp socket")),
    };
    udp_socket.set_write_timeout(Some(Duration::from_millis(500)))?;
    udp_socket.set_read_timeout(Some(Duration::from_millis(500)))?;

    match side.as_str() {
        SIDE_CLIENT => start_client_process(tun_fd, udp_socket, client_addr, stop_signal),
        SIDE_SERVER => start_process_threads(tun_fd, udp_socket, client_addr, stop_signal),
        _ => Err(new_io_err("unknown side to make initializing handshake")),
    }
}

fn start_client_process(
    tun_fd: File,
    udp_socket: UdpSocket,
    client_addr: Arc<RwLock<SocketAddr>>,
    stop_signal: Arc<AtomicBool>,
) -> std::io::Result<()> {
    udp_socket.connect(*client_addr.read().map_err(map_io_err)?)?;
    start_process_threads(tun_fd, udp_socket, client_addr, stop_signal)
}

fn start_process_threads(
    tun_fd: File,
    udp_socket: UdpSocket,
    client_addr: Arc<RwLock<SocketAddr>>,
    stop_signal: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let tun_fd_ = tun_fd.try_clone()?;
    let udp_socket_ = udp_socket.try_clone()?;
    let client_addr_ = client_addr.clone();
    let stop_signal_ = stop_signal.clone();
    let th: JoinHandle<()> = thread::spawn(move || {
        if let Err(e) = tun_process(tun_fd_, udp_socket_, client_addr_, stop_signal_) {
            eprintln!("Failed to run TUN process: {e}");
        }
    });
    rpc_process(tun_fd, udp_socket, client_addr, stop_signal)?;
    th.join().map_err(|_| new_io_err("failed to waiting tun process thread"))
}

fn tun_process(
    mut tun_fd: File,
    udp_socket: UdpSocket,
    client_addr: Arc<RwLock<SocketAddr>>,
    stop_signal: Arc<AtomicBool>,
) -> std::io::Result<()> {
    loop {
        if stop_signal.load(Ordering::Relaxed) {
            eprintln!("Stop signal received for TUN process");
            return Ok(());
        }
        let mut buffer = vec![0; MTU];
        match tun_fd.read(&mut buffer) {
            Ok(n) => {
                let buffer = &buffer[..n];
                eprintln!("Received packet from TUN: {:?}", buffer);
                udp_socket.send_to(buffer, *client_addr.read().map_err(map_io_err)?)?;
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
    stop_signal: Arc<AtomicBool>,
) -> std::io::Result<()> {
    loop {
        if stop_signal.load(Ordering::Relaxed) {
            eprintln!("Stop signal received for RPC process");
            return Ok(());
        }
        let mut buffer = vec![0; MTU];
        match udp_socket.recv_from(&mut buffer) {
            Ok((n, addr)) => {
                let buffer = &buffer[..n];
                eprintln!("Received packet from RPC: {:?}", buffer);
                if client_addr.read().map_err(map_io_err)?.clone().ne(&addr) {
                    eprintln!("Connected new client {addr}");
                    *client_addr.write().map_err(map_io_err)? = addr;
                    continue;
                }
                let _ = tun_fd.write(buffer)?;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == ErrorKind::ConnectionRefused => continue,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn new_io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}
