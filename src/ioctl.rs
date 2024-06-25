use std::os::fd::AsRawFd;

use libc::{c_ulong, c_void};

pub(crate) fn ioctl<T>(fd: &impl AsRawFd, request: c_ulong, arg: &mut T) -> std::io::Result<()> {
    let arg: *mut c_void = arg as *mut _ as *mut c_void;
    #[cfg(target_env = "musl")]
    let res = unsafe { libc::ioctl(fd.as_raw_fd().as_raw_fd(), request as i32, arg) };
    #[cfg(not(target_env = "musl"))]
    let res = unsafe { libc::ioctl(fd.as_raw_fd().as_raw_fd(), request, arg) };
    if res < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
