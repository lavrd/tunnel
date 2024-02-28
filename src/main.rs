use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, UdpSocket},
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    thread,
    time::Duration,
};

use ipnet::Ipv4Net;
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};

mod ioctl;
mod linux;

const MTU: usize = 512;

const SIDE_CLIENT: &str = "client";
const SIDE_SERVER: &str = "server";

const UDP_SOCKET_PORT: &str = "6688";

const INIT_MESSAGE: &[u8] = b"init";

static STOP_SIGNAL: AtomicBool = AtomicBool::new(false);
static ACTIVE_THREADS: AtomicU8 = AtomicU8::new(2);

fn main() -> std::io::Result<()> {
    let name = std::env::args().nth(1).ok_or_else(|| new_io_err("failed to find arg with name"))?;
    let ip: Ipv4Net = std::env::args()
        .nth(2)
        .ok_or_else(|| new_io_err("failed to find arg with ip"))?
        .parse()
        .map_err(map_io_err)?;
    let side = std::env::args().nth(3).ok_or_else(|| new_io_err("failed to find arg with side"))?;
    eprintln!("Starting TUN device with '{}' name and '{}' IP on {}", name, ip, side);

    process(name, ip, side)?;

    let mut sigs = Signals::new(TERM_SIGNALS)?;
    sigs.into_iter().next().ok_or_else(|| new_io_err("failed to wait for termination signal"))?;
    eprintln!("Received termination signal");
    STOP_SIGNAL.store(true, Ordering::Relaxed);
    while ACTIVE_THREADS.load(Ordering::Relaxed) != 0 {}
    Ok(())
}

pub(crate) fn map_io_err<T: ToString>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string().as_str())
}

pub(crate) fn map_io_err_msg<T: ToString>(e: T, msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{}: {}", e.to_string(), msg))
}

fn process(name: String, ip: Ipv4Net, side: String) -> std::io::Result<()> {
    let iface = linux::Interface::new(name, ip, MTU)?;
    let tun_fd = iface.into_tun_fd();

    let udp_socket = match side.as_str() {
        SIDE_CLIENT => UdpSocket::bind("0.0.0.0:0")?,
        SIDE_SERVER => UdpSocket::bind(format!("0.0.0.0:{UDP_SOCKET_PORT}"))?,
        _ => return Err(new_io_err("unknown side to create new udp socket")),
    };
    udp_socket.set_write_timeout(Some(Duration::from_millis(100)))?;
    udp_socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    let client_addr: Option<SocketAddr> = match side.as_str() {
        SIDE_CLIENT => {
            udp_socket.connect(format!("164.92.207.87:{UDP_SOCKET_PORT}"))?;
            udp_socket.send(INIT_MESSAGE)?;
            None
        }
        SIDE_SERVER => {
            let mut buffer = vec![0; MTU];
            loop {
                match udp_socket.recv_from(&mut buffer) {
                    Ok((n, client_addr)) => {
                        let buffer = &buffer[..n];
                        if buffer.ne(INIT_MESSAGE) {
                            continue;
                        }
                        break Some(client_addr);
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                }
            }
        }
        _ => return Err(new_io_err("unknown side to make initializing handshake")),
    };

    let tun_fd_ = tun_fd.try_clone()?;
    let udp_socket_ = udp_socket.try_clone()?;
    thread::spawn(move || {
        if let Err(e) = tun_process(tun_fd_, udp_socket_, client_addr) {
            eprintln!("Failed to run TUN process: {e}");
            std::process::exit(1);
        }
    });
    thread::spawn(move || {
        if let Err(e) = client_server_process(tun_fd, udp_socket) {
            eprintln!("Failed to run client server communication process: {e}");
            std::process::exit(1);
        }
    });
    Ok(())
}

fn tun_process(
    mut tun_fd: File,
    udp_socket: UdpSocket,
    client_addr: Option<SocketAddr>,
) -> std::io::Result<()> {
    loop {
        if STOP_SIGNAL.load(Ordering::Relaxed) {
            ACTIVE_THREADS.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
        let mut buffer = vec![0; MTU];
        match tun_fd.read(&mut buffer) {
            Ok(n) => {
                let buffer = &buffer[..n];
                eprintln!("Received packet from TUN: {:?}", buffer);
                if let Some(client_addr) = client_addr {
                    udp_socket.send_to(buffer, client_addr)?;
                } else {
                    udp_socket.send(buffer)?;
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

fn client_server_process(mut tun_fd: File, udp_socket: UdpSocket) -> std::io::Result<()> {
    loop {
        if STOP_SIGNAL.load(Ordering::Relaxed) {
            ACTIVE_THREADS.fetch_sub(1, Ordering::Relaxed);
            return Ok(());
        }
        let mut buffer = vec![0; MTU];
        match udp_socket.recv(&mut buffer) {
            Ok(n) => {
                let buffer = &buffer[..n];
                eprintln!("Received packet from client or server: {:?}", buffer);
                let _ = tun_fd.write(buffer)?;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

fn new_io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}
