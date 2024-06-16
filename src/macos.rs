use std::fs::File;

use ipnet::Ipv4Net;

pub(crate) struct Interface {
    tun_fd: File,
}

impl Interface {
    pub(crate) fn new(
        _name: String,
        _ip: Ipv4Net,
        _tun_device_mtu: usize,
    ) -> std::io::Result<Self> {
        Ok(Self {
            tun_fd: File::open("/dev/null")?,
        })
    }

    pub(crate) fn into_tun_fd(self) -> File {
        self.tun_fd
    }
}
