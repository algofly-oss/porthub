//! Darwin's utun control unit is assigned before an interface is attached.
//! Binding the exact old unit fails while its original control block exists.
//! No connect, interface configuration, or change to the reused index occurs.
use anyhow::{ensure, Context, Result};
use std::{
    ffi::CStr,
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

fn unit(name: &CStr) -> Result<u32> {
    let name = name.to_str()?;
    let suffix = name.strip_prefix("utun").context("not a Darwin utun")?;
    let number: u32 = suffix.parse()?;
    ensure!(number.to_string() == suffix, "noncanonical utun name");
    number.checked_add(1).context("utun unit out of range")
}

fn reserve(unit: u32) -> Result<OwnedFd> {
    let raw = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let fd = socket.as_raw_fd();
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (out, byte) in info.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
        *out = *byte as libc::c_char;
    }
    if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
    let len = size_of::<libc::sockaddr_ctl>();
    addr.sc_len = len as u8;
    addr.sc_family = libc::AF_SYSTEM as u8;
    addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = unit;
    if unsafe { libc::bind(fd, (&raw const addr).cast(), len as libc::socklen_t) } != 0 {
        return Err(io::Error::last_os_error()).context("old utun unit unavailable");
    }
    Ok(socket)
}

pub(super) fn prove_unused(name: &CStr, own: Ipv4Addr) -> Result<()> {
    let _reservation = reserve(unit(name)?)?;
    let rows = getifaddrs::getifaddrs()?;
    for row in rows {
        ensure!(
            row.name.as_bytes() != name.to_bytes()
                && row.address.ip_addr() != Some(IpAddr::V4(own)),
            "retired utun name or source still present"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires root on Darwin for a kernel-control reservation"]
    fn binding_does_not_attach_and_excludes_a_second_owner() -> Result<()> {
        let number = 30001;
        let first = reserve(number)?;
        let name = c"utun30000";
        assert_eq!(unsafe { libc::if_nametoindex(name.as_ptr()) }, 0);
        let error = reserve(number).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<io::Error>()
                .and_then(io::Error::raw_os_error),
            Some(libc::EBUSY)
        );
        drop(first);
        let loopback = unsafe { libc::if_nametoindex(c"lo0".as_ptr()) };
        ensure!(loopback != 0, "loopback interface missing");
        let old = super::super::Pin::Interface {
            name: name.to_str()?.to_owned(),
            index: loopback,
        };
        // Use a live, unrelated index to exercise the production recovery path.
        super::super::verify_absent(&old, "192.0.2.254".parse()?)?;
        assert!(super::super::verify_absent(&old, Ipv4Addr::LOCALHOST).is_err());
        let _again = reserve(number)?;
        Ok(())
    }

    #[test]
    fn accepts_exact_kernel_names_only() {
        assert_eq!(unit(c"utun0").unwrap(), 1);
        assert_eq!(unit(c"utun6").unwrap(), 7);
        for name in [c"en0", c"utun", c"utun+6", c"utun06", c"utun4294967295"] {
            assert!(unit(name).is_err());
        }
    }
}
