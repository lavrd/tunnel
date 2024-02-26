use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::process::Command;
use std::ptr;
use std::{ffi::CString, fs::File, mem};

use ipnet::Ipv4Net;
use libc::c_int;
use libc::IFF_NOARP;
use libc::IFF_POINTOPOINT;
use libc::IFF_RUNNING;
use libc::IFF_UP;
use libc::O_NONBLOCK;
use libc::O_RDWR;
use libc::{c_char, c_ulong, IFF_NO_PI, IFF_TUN, IFNAMSIZ, SIOCSIFFLAGS, SIOCSIFMTU};

use crate::ioctl::ioctl;
use crate::map_io_err;
use crate::map_io_err_msg;

const TUNSETIFF: c_ulong = 1074025674;

const FLAGS: i16 = (IFF_UP | IFF_POINTOPOINT | IFF_RUNNING | IFF_NOARP) as i16;

#[repr(C)]
struct IfReq {
    name: [c_char; IFNAMSIZ],
    flags: u16,
    _pad: [u8; 40 - 16 - 2],
}

impl IfReq {
    fn new(name: &CString) -> Self {
        let mut if_req: IfReq = unsafe { mem::zeroed() };
        set_name(name, if_req.name.as_mut_ptr());
        if_req
    }
}

#[repr(C)]
struct IfReqMtu {
    name: [c_char; IFNAMSIZ],
    mtu: i32,
}

impl IfReqMtu {
    fn new(name: &CString, mtu: i32) -> Self {
        let mut if_req_mtu: IfReqMtu = unsafe { mem::zeroed() };
        set_name(name, if_req_mtu.name.as_mut_ptr());
        if_req_mtu.mtu = mtu;
        if_req_mtu
    }
}

#[repr(C)]
struct IfReqFlags {
    name: [c_char; IFNAMSIZ],
    flags: i16,
}

impl IfReqFlags {
    fn new(name: &CString) -> Self {
        let mut if_req_flags: IfReqFlags = unsafe { mem::zeroed() };
        set_name(name, if_req_flags.name.as_mut_ptr());
        if_req_flags.flags = FLAGS;
        if_req_flags
    }
}

pub(crate) struct Interface {
    tun_fd: File,
}

impl Interface {
    pub(crate) fn new(
        mut name: String,
        ips: &[Ipv4Net],
        tun_device_mtu: usize,
    ) -> std::io::Result<Self> {
        name.truncate(IFNAMSIZ);
        let name = CString::new(name)?;

        let mut if_req = IfReq::new(&name);
        if_req.flags = (IFF_TUN | IFF_NO_PI) as u16;

        let tun_fd = open_non_blocking("/dev/net/tun")?;
        ioctl(&tun_fd, TUNSETIFF, &mut if_req)
            .map_err(|e| map_io_err_msg(e, "failed to create tun device"))?;
        let udp_socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0))?;
        let ip_fd = udp_socket.as_raw_fd();

        for ipnet in ips.iter() {
            let status = Command::new("ip")
                .args(vec![
                    "addr",
                    "add",
                    &ipnet.to_string(),
                    "dev",
                    &name.to_string_lossy(),
                ])
                .status()
                .map_err(|e| map_io_err_msg(e, "failed to run the `ip` command"))?;
            if !status.success() {
                return Err(map_io_err("failed to set address"));
            }
        }
        {
            let mut if_req_mtu = IfReqMtu::new(&name, tun_device_mtu as i32);
            ioctl(&ip_fd, SIOCSIFMTU, &mut if_req_mtu)
                .map_err(|e| map_io_err_msg(e, "failed to set mtu"))?;
        }
        {
            let mut if_req_flags = IfReqFlags::new(&name);
            ioctl(&ip_fd, SIOCSIFFLAGS, &mut if_req_flags)
                .map_err(|e| map_io_err_msg(e, "failed to set network interface flags"))?;
        }
        Ok(Self { tun_fd })
    }

    pub(crate) fn into_tun_fd(self) -> File {
        self.tun_fd
    }
}

fn open_non_blocking(filename: &str) -> std::io::Result<File> {
    let ret = wrap(unsafe {
        libc::open(
            CString::new(filename).unwrap().as_c_str().as_ptr() as *const c_char,
            O_NONBLOCK | O_RDWR,
        )
    })
    .map_err(|e| map_io_err_msg(e, "failed to open"))?;
    Ok(unsafe { File::from_raw_fd(ret) })
}

fn set_name<T>(name: &CString, dst: *mut T) {
    unsafe {
        ptr::copy_nonoverlapping(
            name.as_ptr() as *const c_char,
            dst as *mut _,
            name.as_bytes().len(),
        )
    }
}

fn wrap(ret: c_int) -> std::io::Result<c_int> {
    if ret == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}
