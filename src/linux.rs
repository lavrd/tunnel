use std::ffi::CString;
use std::fs::File;
use std::mem;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::ptr;

use libc::AF_INET;
use libc::IFF_NO_PI;
use libc::IFF_NOARP;
use libc::IFF_POINTOPOINT;
use libc::IFF_RUNNING;
use libc::IFF_TUN;
use libc::IFF_UP;
use libc::IFNAMSIZ;
use libc::O_NONBLOCK;
use libc::O_RDONLY;
use libc::O_RDWR;
use libc::SIOCSIFADDR;
use libc::SIOCSIFDSTADDR;
use libc::SIOCSIFFLAGS;
use libc::SIOCSIFMTU;
use libc::SIOCSIFNETMASK;
use libc::c_char;
use libc::c_int;
use libc::c_ulong;
use libc::c_void;
use libc::in_addr;
use libc::sockaddr_in;
use log::debug;
use log::warn;

use crate::map_io_err;
use crate::map_io_err_msg;
use crate::tunnel;

// We got this value from:
// https://cs.opensource.google/go/go/+/refs/tags/go1.23.1:src/syscall/zerrors_linux_amd64.go;l=1161
// Value from file below is 0x400454ca, but it is in hex, after converting it to dec it is: 1074025674.
// Alternative way to use it, it is use nix crate:
/*
```rust
nix::ioctl_write_ptr!(tunsetiff, b'T', 202, libc::c_int);
# Then use it like:
tunsetiff(tun_fd.as_raw_fd(), &mut if_req as *mut _ as *mut _)
```
*/
const TUNSETIFF: c_ulong = 1074025674;

// Check what these flags mean in following docs:
// https://man7.org/linux/man-pages/man7/netdevice.7.html
const FLAGS: i16 = (IFF_UP | IFF_POINTOPOINT | IFF_RUNNING | IFF_NOARP) as i16;

// Check this structure in:
// https://man7.org/linux/man-pages/man7/netdevice.7.html
#[repr(C)]
struct IfReq {
    name: [c_char; IFNAMSIZ],
    flags: u16,
    // So, this structure should be aligned to pass it by pointer to system call.
    // As we do not use all available fields, we need to have padding to avoid memory corruption.
    // All fields are 40 bytes.
    // "name" field is 16 bytes.
    // "flags" field is 2 bytes.
    // That's why we have 40-16-2.
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
struct IfReqAddr {
    name: [c_char; IFNAMSIZ],
    addr: sockaddr_in,
}

impl IfReqAddr {
    fn new(name: &CString, ip: Ipv4Addr) -> Self {
        let mut if_req_addr: Self = unsafe { mem::zeroed() };
        set_name(name, if_req_addr.name.as_mut_ptr());
        if_req_addr.addr = sockaddr_in {
            sin_family: AF_INET as u16,
            sin_zero: [0; 8],
            sin_port: 0,
            sin_addr: in_addr {
                s_addr: u32::from_le_bytes(ip.octets()),
            },
        };
        if_req_addr
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

pub(crate) struct Device {
    tun_fd: File,
}

impl Device {
    pub(crate) fn new(
        mut name: String,
        ip: String,
        tun_device_mtu: usize,
    ) -> std::io::Result<Self> {
        name.truncate(IFNAMSIZ);
        let name = CString::new(name)?;

        let (addr, netmask): (Ipv4Addr, Ipv4Addr) = tunnel::parse_ipv4(&ip)?;

        /*
            Open tun device and set new interface with flags.
        */
        let tun_fd = open_non_blocking("/dev/net/tun")?;
        let mut if_req = IfReq::new(&name);
        // Information about flags: https://www.kernel.org/doc/Documentation/networking/tuntap.txt
        if_req.flags = (IFF_TUN | IFF_NO_PI) as u16;
        ioctl(&tun_fd, TUNSETIFF, &mut if_req)
            .map_err(|e| map_io_err_msg(e, "failed to create tun device"))?;
        // We are not sure that it can work with ipv6, so let's disable it by default.
        disable_ipv6(&name)?;

        /*
            Following code is the same as: ip addr add 10.0.0.1/24 dev tun0
        */
        let udp_socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0))?;
        let ip_fd = udp_socket.as_raw_fd();
        let mut if_req_addr = IfReqAddr::new(&name, addr);
        ioctl(&ip_fd, SIOCSIFADDR, &mut if_req_addr)
            .map_err(|e| map_io_err_msg(e, "failed to set device address"))?;
        let mut if_req_dst = IfReqAddr::new(&name, addr);
        ioctl(&ip_fd, SIOCSIFDSTADDR, &mut if_req_dst)
            .map_err(|e| map_io_err_msg(e, "failed to set destination address"))?;
        let mut if_req_mask = IfReqAddr::new(&name, netmask);
        ioctl(&ip_fd, SIOCSIFNETMASK, &mut if_req_mask)
            .map_err(|e| map_io_err_msg(e, "failed to set network mask"))?;
        let mut if_req_mtu = IfReqMtu::new(&name, tun_device_mtu as i32);
        ioctl(&ip_fd, SIOCSIFMTU, &mut if_req_mtu)
            .map_err(|e| map_io_err_msg(e, "failed to set mtu"))?;
        let mut if_req_flags = IfReqFlags::new(&name);
        ioctl(&ip_fd, SIOCSIFFLAGS, &mut if_req_flags)
            .map_err(|e| map_io_err_msg(e, "failed to set network device flags"))?;

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

fn ioctl<T>(fd: &impl AsRawFd, request: c_ulong, arg: &mut T) -> std::io::Result<()> {
    let arg: *mut c_void = arg as *mut _ as *mut c_void;
    #[cfg(target_env = "musl")]
    let res = unsafe { libc::ioctl(fd.as_raw_fd(), request as i32, arg) };
    #[cfg(not(target_env = "musl"))]
    let res = unsafe { libc::ioctl(fd.as_raw_fd(), request, arg) };
    if res < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn disable_ipv6(iface_name: &CString) -> std::io::Result<()> {
    if !is_ipv6_enabled(iface_name)? {
        debug!("ipv6 protocol was disabled for interface");
        return Ok(());
    }
    debug!("ipv6 protocol is active for interface");
    let fd = match open_ipv6_fd(iface_name, O_RDWR)? {
        Some(fd) => fd,
        None => return Ok(()), // we can't disable ipv6 if we cannot open it
    };
    if unsafe { libc::write(fd, b"1".as_ptr() as *const _, 1) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::close(fd) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if !is_ipv6_enabled(iface_name)? {
        debug!("ipv6 protocol is disabled for interface");
        return Ok(());
    }
    debug!("ipv6 protocol is still active for interface");
    Ok(())
}

fn is_ipv6_enabled(iface_name: &CString) -> std::io::Result<bool> {
    let fd = match open_ipv6_fd(iface_name, O_RDONLY)? {
        Some(fd) => fd,
        None => return Ok(false), // we cannot check that ipv6 is enabled if we cannot open it
    };
    let mut buf = [0u8; 2];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n < 0 {
        return Err(map_io_err_msg(std::io::Error::last_os_error(), "failed to read from ipv6 fd"));
    }
    if unsafe { libc::close(fd) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if let Some(flag) = (buf[0] as char).to_digit(10) {
        match flag {
            0 => return Ok(true),  // enabled
            1 => return Ok(false), // disabled
            k => return Err(map_io_err(format!("unknown value after read from ipv6 fd: {}", k))),
        }
    }
    // Cannot check as cannot convert read value.
    Ok(false)
}

fn open_ipv6_fd(iface_name: &CString, oflag: c_int) -> std::io::Result<Option<i32>> {
    let fd = unsafe {
        libc::open(
            format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", iface_name.to_string_lossy())
                .as_str()
                .as_ptr() as *const _,
            oflag,
        )
    };
    if fd < 0 {
        let last_os_error = std::io::Error::last_os_error();
        match last_os_error.raw_os_error() {
            // 30 means Read-only file system error.
            Some(30) => {
                warn!("failed to open ipv6 fd: file system is read-only: {}", last_os_error);
                return Ok(None);
            }
            Some(2) => {
                warn!("failed to open ipv6 fd: file is not exists: {}", last_os_error);
                return Ok(None);
            }
            Some(n) => {
                return Err(map_io_err_msg(
                    last_os_error,
                    &format!("failed to open ipv6 fd: unknown os error: {n}"),
                ));
            }
            _ => return Err(map_io_err_msg(last_os_error, "failed to open ipv6 fd")),
        }
    }
    Ok(Some(fd))
}
