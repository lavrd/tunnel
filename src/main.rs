use std::{
    io::{ErrorKind, Read, Write},
    net::TcpListener,
    sync::mpsc,
    thread,
    time::Duration,
};

use etherparse::{IpNumber, Ipv4Slice};
use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};

mod ioctl;
mod linux;

const MTU: usize = 512;

fn main() -> std::io::Result<()> {
    let name = std::env::args().nth(1).ok_or_else(|| new_io_err("failed to find arg with name"))?;
    let ip = std::env::args().nth(2).ok_or_else(|| new_io_err("failed to find arg with ip"))?;
    eprintln!("Starting TUN device with '{}' name and '{}' IP", name, ip);

    let (stop_s, stop_r) = mpsc::channel::<()>();
    let (stop_cb_s, stop_cb_r) = mpsc::channel::<()>();

    thread::spawn(move || -> std::io::Result<()> {
        let iface = linux::Interface::new(name, &[ip.parse().map_err(map_io_err)?], MTU)?;
        let mut tun_fd = iface.into_tun_fd();

        let listener = TcpListener::bind("0.0.0.0:6688")?;
        let (mut socket, _) = listener.accept()?;
        let mut buffer = vec![0; MTU];
        let n = socket.read(&mut buffer)?;
        let _ = tun_fd.write(&buffer[..n])?;

        loop {
            if stop_r.try_recv().is_ok() {
                stop_cb_s.send(()).map_err(map_io_err)?;
                return Ok(());
            }
            let mut buffer = vec![0; MTU];
            match tun_fd.read(&mut buffer) {
                Ok(n) => {
                    let buffer = &buffer[..n];
                    eprintln!("Received packet: {:?}", buffer);
                    let ipv4_packet = Ipv4Slice::from_slice(buffer).map_err(map_io_err)?;
                    if ipv4_packet.header().protocol() != IpNumber::ICMP {
                        continue;
                    }
                    let _ = socket.write(buffer)?;
                    std::process::exit(0);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
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

fn new_io_err(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}
