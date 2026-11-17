//! Read-only birth proof for the kernel-created own /32 on fresh utun.
//! Local delivery is performed by the real production OwnedPacketLoop. No
//! PF_ROUTE ADD/DELETE/CHANGE, loopback route, or foreign route adoption.
use anyhow::{ensure, Context, Result};
use std::net::Ipv4Addr;
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    index: u32,
    flags: i32,
    gateway: Vec<u8>,
    source: Ipv4Addr,
}
fn positive_before_absence(before: Option<&[Stamp]>) -> Result<()> {
    ensure!(
        before.is_some_and(|rows| rows.is_empty()),
        "own-route absence before fresh address creation is not proven; preserved"
    );
    Ok(())
}
// Constructor-only provenance: the successful fresh address assignment is the
// native birth event. This cannot authorize any row visible before assignment,
// a different source generation, or a row with merely similar route fields.
fn address_created_row(
    before: Option<&[Stamp]>,
    after: &[Stamp],
    own: Ipv4Addr,
    source_index: u32,
    current_index: u32,
    source_present: bool,
) -> Result<Option<Stamp>> {
    positive_before_absence(before)?;
    ensure!(
        source_present && source_index != 0 && current_index == source_index,
        "fresh native address generation changed; preserved"
    );
    if after.is_empty() {
        return Ok(None);
    }
    ensure!(
        after.len() == 1,
        "fresh native own-route identity is ambiguous; preserved"
    );
    let row = &after[0];
    ensure!(
        row.index == source_index && row.source == own && row.flags == 0x200005,
        "native address-created own-route shape differs; preserved"
    );
    ensure!(
        row.gateway.len() == 16
            && row.gateway[0] == 16
            && row.gateway[1] == 2
            && row.gateway[2..4] == [0, 0]
            && row.gateway[4..8] == own.octets()
            && row.gateway[8..].iter().all(|byte| *byte == 0),
        "native address-created route gateway is not the exact owned IPv4 address; preserved"
    );
    Ok(Some(row.clone()))
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use route_manager::Route;
    use std::{ffi::CString, net::IpAddr};
    const CAP: usize = 4 * 1024 * 1024;
    fn source(name: &str, index: u32, own: Ipv4Addr) -> Result<()> {
        let c = CString::new(name)?;
        ensure!(
            unsafe { libc::if_nametoindex(c.as_ptr()) } == index,
            "native source generation changed"
        );
        let mut list = std::ptr::null_mut();
        ensure!(
            unsafe { libc::getifaddrs(&mut list) } == 0,
            "cannot verify native source address"
        );
        struct List(*mut libc::ifaddrs);
        impl Drop for List {
            fn drop(&mut self) {
                unsafe { libc::freeifaddrs(self.0) }
            }
        }
        let _list = List(list);
        let mut p = list;
        let mut found = false;
        let mut n = 0;
        while !p.is_null() {
            n += 1;
            ensure!(n <= 65536, "native address inventory exceeds bound");
            let a = unsafe { &*p };
            if !a.ifa_name.is_null()
                && unsafe { std::ffi::CStr::from_ptr(a.ifa_name) } == c.as_c_str()
                && !a.ifa_addr.is_null()
                && unsafe { (*a.ifa_addr).sa_family as i32 } == libc::AF_INET
            {
                let ip = unsafe { &*(a.ifa_addr as *const libc::sockaddr_in) };
                if Ipv4Addr::from(ip.sin_addr.s_addr.to_ne_bytes()) == own {
                    found = true;
                }
            }
            p = a.ifa_next;
        }
        ensure!(found, "owned native source address disappeared");
        Ok(())
    }
    fn inventory(own: Ipv4Addr) -> Result<Vec<Stamp>> {
        let mut mib = [
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            libc::AF_INET,
            libc::NET_RT_DUMP,
            0,
        ];
        let mut len = 0;
        ensure!(
            unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    6,
                    std::ptr::null_mut(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            } == 0,
            "cannot size native local route inventory"
        );
        ensure!(len <= CAP, "native route inventory exceeds bound");
        let mut bytes = vec![0u8; len];
        ensure!(
            unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    6,
                    bytes.as_mut_ptr().cast(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            } == 0,
            "native route inventory changed or failed"
        );
        bytes.truncate(len);
        parse(&bytes, own)
    }
    fn parse(bytes: &[u8], own: Ipv4Addr) -> Result<Vec<Stamp>> {
        ensure!(bytes.len() <= CAP, "native route inventory exceeds bound");
        let mut pos = 0;
        let mut rows = Vec::new();
        let mut count = 0;
        while pos < bytes.len() {
            count += 1;
            ensure!(count <= 65536, "native route count exceeds bound");
            let hs = std::mem::size_of::<libc::rt_msghdr>();
            ensure!(bytes.len() - pos >= hs, "truncated native route header");
            let h = unsafe {
                std::ptr::read_unaligned(bytes[pos..].as_ptr().cast::<libc::rt_msghdr>())
            };
            let end = pos + usize::from(h.rtm_msglen);
            ensure!(
                h.rtm_msglen as usize >= hs
                    && end <= bytes.len()
                    && h.rtm_version == 5
                    && h.rtm_errno == 0,
                "invalid native route header"
            );
            let mut at = pos + hs;
            let mut dst = None;
            let mut gateway = None;
            let mut source = None;
            for bit in 0..8 {
                if h.rtm_addrs & (1 << bit) == 0 {
                    continue;
                }
                ensure!(at + 2 <= end, "truncated route sockaddr");
                let len = bytes[at] as usize;
                let step = if len == 0 { 4 } else { (len + 3) & !3 };
                ensure!(
                    (len == 0 || len >= 2) && at + step <= end && len <= step,
                    "invalid route sockaddr"
                );
                if bit == 0 && len >= 8 && bytes[at + 1] as i32 == libc::AF_INET {
                    dst = Some(Ipv4Addr::new(
                        bytes[at + 4],
                        bytes[at + 5],
                        bytes[at + 6],
                        bytes[at + 7],
                    ));
                }
                if bit == 5 && len >= 8 && bytes[at + 1] as i32 == libc::AF_INET {
                    source = Some(Ipv4Addr::new(
                        bytes[at + 4],
                        bytes[at + 5],
                        bytes[at + 6],
                        bytes[at + 7],
                    ));
                }
                if bit == 1 {
                    ensure!(len <= 128, "native gateway exceeds bound");
                    gateway = Some(bytes[at..at + len].to_vec());
                }
                at += step;
            }
            if dst == Some(own) {
                ensure!(rows.len() < 16, "ambiguous local route inventory");
                ensure!(
                    h.rtm_flags & libc::RTF_HOST != 0,
                    "own address has non-host exact route"
                );
                rows.push(Stamp {
                    index: u32::from(h.rtm_index),
                    flags: h.rtm_flags,
                    gateway: gateway.context("local route gateway absent")?,
                    source: source.context("local route source-address ownership absent")?,
                });
            }
            pos = end;
        }
        Ok(rows)
    }

    pub struct BeforeAddress {
        own: Ipv4Addr,
        rows: Result<Vec<Stamp>>,
    }
    impl BeforeAddress {
        pub fn observe(own: Ipv4Addr) -> Self {
            Self {
                own,
                rows: inventory(own),
            }
        }
        pub fn validate(&self) -> Result<()> {
            positive_before_absence(self.rows.as_ref().ok().map(Vec::as_slice))
        }
    }
    pub struct AddressRoute {
        own: Ipv4Addr,
        index: u32,
        name: String,
        stamp: Stamp,
    }
    impl AddressRoute {
        pub fn confirm(
            name: &str,
            index: u32,
            own: Ipv4Addr,
            before: BeforeAddress,
        ) -> Result<Self> {
            ensure!(
                before.own == own,
                "address birth proof belongs to another source"
            );
            source(name, index, own)?;
            let rows = inventory(own)?;
            let stamp = address_created_row(
                before.rows.as_ref().ok().map(Vec::as_slice),
                &rows,
                own,
                index,
                index,
                true,
            )?
            .context("native own host route absent after fresh address assignment")?;
            Ok(Self {
                own,
                index,
                name: name.into(),
                stamp,
            })
        }
        pub fn verify(&self) -> Result<()> {
            source(&self.name, self.index, self.own)?;
            ensure!(
                inventory(self.own)? == [self.stamp.clone()],
                "native address-born route changed; source must retire"
            );
            Ok(())
        }
        pub fn matches(&self, route: &Route) -> bool {
            route.destination() == IpAddr::V4(self.own)
                && route.prefix() == 32
                && route.if_index() == Some(self.index)
        }
    }
}
#[cfg(target_os = "macos")]
pub(super) use native::{AddressRoute, BeforeAddress};
#[cfg(test)]
mod tests {
    use super::*;
    fn own() -> Ipv4Addr {
        Ipv4Addr::new(10, 254, 251, 1)
    }
    fn row() -> Stamp {
        let mut gateway = vec![0; 16];
        gateway[0] = 16;
        gateway[1] = 2;
        gateway[4..8].copy_from_slice(&own().octets());
        Stamp {
            index: 12,
            flags: 0x200005,
            gateway,
            source: own(),
        }
    }
    #[test]
    fn birth_requires_positive_empty_before_and_live_exact_source() {
        let rows = [row()];
        assert!(address_created_row(None, &rows, own(), 12, 12, true).is_err());
        assert!(address_created_row(Some(&rows), &rows, own(), 12, 12, true).is_err());
        assert!(address_created_row(Some(&[]), &rows, own(), 12, 13, true).is_err());
        assert!(address_created_row(Some(&[]), &rows, own(), 12, 12, false).is_err());
        assert_eq!(
            address_created_row(Some(&[]), &rows, own(), 12, 12, true).unwrap(),
            Some(row())
        );
    }
    #[test]
    fn foreign_ambiguous_or_changed_native_rows_are_not_adopted() {
        let r = row();
        assert!(
            address_created_row(Some(&[]), &[r.clone(), r.clone()], own(), 12, 12, true).is_err()
        );
        for field in 0..5 {
            let mut bad = r.clone();
            match field {
                0 => bad.index = 1,
                1 => bad.source = Ipv4Addr::LOCALHOST,
                2 => bad.flags |= 2,
                3 => bad.gateway[4] = 127,
                _ => bad.gateway[15] = 1,
            };
            assert!(address_created_row(Some(&[]), &[bad], own(), 12, 12, true).is_err());
        }
    }
}
