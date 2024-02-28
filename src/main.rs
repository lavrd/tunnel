use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc,
    },
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

static STOP_SIGNAL: AtomicBool = AtomicBool::new(false);
static ACTIVE_THREADS: AtomicU8 = AtomicU8::new(0);

fn main() -> std::io::Result<()> {
    let name = std::env::args().nth(1).ok_or_else(|| new_io_err("failed to find arg with name"))?;
    let ip: Ipv4Net = std::env::args()
        .nth(2)
        .ok_or_else(|| new_io_err("failed to find arg with ip"))?
        .parse()
        .map_err(map_io_err)?;
    let side = std::env::args().nth(3).ok_or_else(|| new_io_err("failed to find arg with side"))?;
    eprintln!("Starting TUN device with '{}' name and '{}' IP on {}", name, ip, side);

    start_process(name, ip, side)?;

    let mut sigs = Signals::new(TERM_SIGNALS)?;
    sigs.into_iter().next().ok_or_else(|| new_io_err("failed to wait for termination signal"))?;
    eprintln!("Received termination signal");
    STOP_SIGNAL.store(true, Ordering::Relaxed);
    while ACTIVE_THREADS.load(Ordering::Relaxed) != 0 {
        std::hint::spin_loop()
    }
    Ok(())
}

pub(crate) fn map_io_err<T: ToString>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string().as_str())
}

pub(crate) fn map_io_err_msg<T: ToString>(e: T, msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{}: {}", e.to_string(), msg))
}

fn start_process(name: String, ip: Ipv4Net, side: String) -> std::io::Result<()> {
    let iface = linux::Interface::new(name, ip, MTU)?;
    let tun_fd = iface.into_tun_fd();

    let udp_socket = match side.as_str() {
        SIDE_CLIENT => UdpSocket::bind("0.0.0.0:0")?,
        SIDE_SERVER => UdpSocket::bind(format!("0.0.0.0:{UDP_SOCKET_PORT}"))?,
        _ => return Err(new_io_err("unknown side to create new udp socket")),
    };
    udp_socket.set_write_timeout(Some(Duration::from_millis(100)))?;
    udp_socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    match side.as_str() {
        SIDE_CLIENT => start_process_inner(tun_fd, udp_socket, start_client_process),
        SIDE_SERVER => start_process_inner(tun_fd, udp_socket, start_server_process),
        _ => return Err(new_io_err("unknown side to make initializing handshake")),
    };
    Ok(())
}

fn start_process_inner<F>(tun_fd: File, udp_socket: UdpSocket, f: F)
where
    F: FnOnce(File, UdpSocket) -> std::io::Result<()> + Send + 'static,
{
    ACTIVE_THREADS.fetch_add(1, Ordering::Relaxed);
    thread::spawn(move || {
        if let Err(e) = f(tun_fd, udp_socket) {
            final_error(e, "Failed to start server process")
        }
        ACTIVE_THREADS.fetch_sub(1, Ordering::Relaxed);
    });
}

fn start_client_process(tun_fd: File, udp_socket: UdpSocket) -> std::io::Result<()> {
    udp_socket.connect(format!("164.92.207.87:{UDP_SOCKET_PORT}"))?;
    start_process_threads(&tun_fd, &udp_socket, None)
}

fn start_server_process(tun_fd: File, udp_socket: UdpSocket) -> std::io::Result<()> {
    loop {
        let client_addr: SocketAddr = loop {
            if STOP_SIGNAL.load(Ordering::Relaxed) {
                eprintln!("Exiting waiting new client loop");
                return Ok(());
            }
            match udp_socket.recv_from(&mut []) {
                Ok((_, client_addr)) => {
                    break client_addr;
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        };
        start_process_threads(&tun_fd, &udp_socket, Some(client_addr))?;
    }
}

fn start_process_threads(
    tun_fd: &File,
    udp_socket: &UdpSocket,
    client_addr: Option<SocketAddr>,
) -> std::io::Result<()> {
    const THREADS: u8 = 2;
    ACTIVE_THREADS.fetch_add(THREADS, Ordering::Relaxed);
    let (res_s, res_r) = mpsc::channel::<std::io::Result<()>>();

    let tun_fd_ = tun_fd.try_clone()?;
    let udp_socket_ = udp_socket.try_clone()?;
    let res_s_ = res_s.clone();
    thread::spawn(move || {
        let res = tun_process(tun_fd_, udp_socket_, client_addr);
        if let Err(e) = res_s_.send(res) {
            final_error(e, "Failed to send tun process result");
        }
    });
    let tun_fd_ = tun_fd.try_clone()?;
    let udp_socket_ = udp_socket.try_clone()?;
    thread::spawn(move || {
        let res = rpc_process(tun_fd_, udp_socket_);
        if let Err(e) = res_s.send(res) {
            final_error(e, "Failed to send rpc process result");
        }
    });

    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..THREADS {
        match res_r.recv() {
            Ok(res) => {
                if res.is_err() {
                    last_err = Some(res.unwrap_err())
                }
            }
            Err(e) => {
                final_error(e, "Failed to receive result from process thread");
            }
        }
    }

    ACTIVE_THREADS.fetch_sub(THREADS, Ordering::Relaxed);
    if let Some(e) = last_err {
        return Err(e);
    }
    Ok(())
}

fn tun_process(
    mut tun_fd: File,
    udp_socket: UdpSocket,
    client_addr: Option<SocketAddr>,
) -> std::io::Result<()> {
    loop {
        if STOP_SIGNAL.load(Ordering::Relaxed) {
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

fn rpc_process(mut tun_fd: File, udp_socket: UdpSocket) -> std::io::Result<()> {
    loop {
        if STOP_SIGNAL.load(Ordering::Relaxed) {
            return Ok(());
        }
        let mut buffer = vec![0; MTU];
        match udp_socket.recv(&mut buffer) {
            Ok(n) => {
                let buffer = &buffer[..n];
                eprintln!("Received packet from RPC: {:?}", buffer);
                let _ = tun_fd.write(buffer)?;
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(ref e) if e.kind() == ErrorKind::ConnectionRefused => continue,
            Err(e) => return Err(e),
        }
    }
}

fn new_io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

fn final_error<T: ToString>(e: T, prefix: &str) {
    eprintln!("{prefix}: {}", e.to_string());
    std::process::exit(1);
}
