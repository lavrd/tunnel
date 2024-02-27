use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, UdpSocket},
    sync::mpsc::{channel, Receiver, Sender},
    thread,
    time::Duration,
};

use etherparse::{IpNumber, Ipv4Slice};
use ipnet::Ipv4Net;
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};

mod ioctl;
mod linux;

const MTU: usize = 512;

const SIDE_CLIENT: &str = "client";
const SIDE_SERVER: &str = "server";

fn main() -> std::io::Result<()> {
    let name = std::env::args().nth(1).ok_or_else(|| new_io_err("failed to find arg with name"))?;
    let ip: Ipv4Net = std::env::args()
        .nth(2)
        .ok_or_else(|| new_io_err("failed to find arg with ip"))?
        .parse()
        .map_err(map_io_err)?;
    let side = std::env::args().nth(3).ok_or_else(|| new_io_err("failed to find arg with side"))?;
    eprintln!("Starting TUN device with '{}' name and '{}' IP on {}", name, ip, side);

    let (stop_s, stop_r) = channel::<()>();
    let (stop_cb_s, stop_cb_r) = channel::<()>();

    thread::spawn(move || {
        if let Err(e) = process(name, ip, side, stop_r, stop_cb_s) {
            eprintln!("Failed to process IP packets: {e}")
        }
    });

    let mut sigs = Signals::new(TERM_SIGNALS)?;
    sigs.into_iter().next().ok_or_else(|| new_io_err("failed to wait for termination signal"))?;
    eprintln!("Received termination signal");
    stop_s.send(()).map_err(map_io_err)?;
    stop_cb_r.recv_timeout(Duration::from_secs(1)).map_err(map_io_err)?;
    Ok(())
}

pub(crate) fn map_io_err<T: ToString>(e: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string().as_str())
}

pub(crate) fn map_io_err_msg<T: ToString>(e: T, msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("{}: {}", e.to_string(), msg))
}

fn process(
    name: String,
    ip: Ipv4Net,
    side: String,
    stop_r: Receiver<()>,
    stop_cb_s: Sender<()>,
) -> std::io::Result<()> {
    let iface = linux::Interface::new(name, ip, MTU)?;
    let tun_fd = iface.into_tun_fd();
    match side.as_str() {
        SIDE_CLIENT => client(tun_fd, stop_r, stop_cb_s),
        SIDE_SERVER => server(tun_fd, stop_r, stop_cb_s),
        _ => Ok(()),
    }
}

fn client(mut tun_fd: File, stop_r: Receiver<()>, stop_cb_s: Sender<()>) -> std::io::Result<()> {
    loop {
        if stop_r.try_recv().is_ok() {
            stop_cb_s.send(()).map_err(map_io_err)?;
            return Ok(());
        }
        let mut buffer = vec![0; MTU];
        match tun_fd.read(&mut buffer) {
            Ok(n) => {
                let buffer = &buffer[..n];
                eprintln!("Received packet from TUN: {:?}", buffer);
                let udp_socket = UdpSocket::bind("0.0.0.0:0")?;
                udp_socket.connect("164.92.207.87:6688")?;
                udp_socket.send(buffer)?;
                let mut buffer = vec![0; MTU];
                let (n, _) = udp_socket.recv_from(&mut buffer)?;
                let buffer = &buffer[..n];
                eprintln!("Received packet from server: {:?}", buffer);
                let _ = tun_fd.write(buffer)?;
                std::process::exit(0);
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

fn server(mut tun_fd: File, stop_r: Receiver<()>, stop_cb_s: Sender<()>) -> std::io::Result<()> {
    let udp_socket = UdpSocket::bind("0.0.0.0:6688")?;
    udp_socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    let (buffer, recv_from): (Vec<u8>, SocketAddr) = loop {
        if stop_r.try_recv().is_ok() {
            stop_cb_s.send(()).map_err(map_io_err)?;
            return Ok(());
        }
        let mut buffer = vec![0; MTU];
        let (n, recv_from) = match udp_socket.recv_from(&mut buffer) {
            Ok((n, recv_from)) => {
                if n == 0 {
                    continue;
                };
                (n, recv_from)
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        };
        buffer.truncate(n);
        break (buffer, recv_from);
    };
    eprintln!("Received packet from client: {:?}", buffer);
    let _ = tun_fd.write(&buffer)?;
    loop {
        if stop_r.try_recv().is_ok() {
            stop_cb_s.send(()).map_err(map_io_err)?;
            return Ok(());
        }
        let mut buffer = vec![0; MTU];
        match tun_fd.read(&mut buffer) {
            Ok(n) => {
                let buffer = &buffer[..n];
                eprintln!("Received packet from TUN: {:?}", buffer);
                let ipv4_packet = Ipv4Slice::from_slice(buffer).map_err(map_io_err)?;
                if ipv4_packet.header().protocol() != IpNumber::ICMP {
                    continue;
                }
                let _ = udp_socket.send_to(buffer, recv_from)?;
                std::process::exit(0);
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

fn new_io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}
