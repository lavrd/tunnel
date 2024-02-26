use std::{
    io::{ErrorKind, Read},
    sync::mpsc,
    thread,
    time::Duration,
};

use signal_hook::{consts::TERM_SIGNALS, iterator::Signals};

mod ioctl;
mod linux;

fn main() -> std::io::Result<()> {
    let name = std::env::args().nth(1).ok_or_else(|| new_io_err("failed to find arg with name"))?;
    let ip = std::env::args().nth(2).ok_or_else(|| new_io_err("failed to find arg with ip"))?;
    eprintln!("Starting TUN device with '{}' name and '{}' IP", name, ip);
    let (stop_s, stop_r) = mpsc::channel::<()>();
    let (stop_cb_s, stop_cb_r) = mpsc::channel::<()>();
    thread::spawn(move || -> std::io::Result<()> {
        let iface = linux::Interface::new(name, &[ip.parse().map_err(map_io_err)?], 512)?;
        let mut tun_fd = iface.into_tun_fd();
        loop {
            if stop_r.try_recv().is_ok() {
                stop_cb_s.send(()).map_err(map_io_err)?;
                return Ok(());
            }
            let mut buffer = vec![0; 512];
            match tun_fd.read(&mut buffer) {
                Ok(n) => {
                    eprintln!("Received packet: {:?}", &buffer[..n]);
                    continue;
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
