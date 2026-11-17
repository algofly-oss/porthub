//! Winsock endpoint ownership. A default same-account bind is not exclusive.
use anyhow::{ensure, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{SocketAddr, SocketAddrV4},
    os::windows::io::AsRawSocket,
};
use tokio::net::{TcpListener, UdpSocket};
use windows_sys::Win32::Networking::WinSock::{
    getsockopt, setsockopt, WSAGetLastError, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
};
fn exclusive(kind: Type, protocol: Protocol) -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, kind, Some(protocol))?;
    socket.set_reuse_address(false)?;
    let enabled = 1i32;
    // Microsoft requires this option BEFORE bind, including same-account peers:
    // https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
    ensure!(
        unsafe {
            setsockopt(
                socket.as_raw_socket() as _,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&enabled as *const i32).cast(),
                std::mem::size_of::<i32>() as i32,
            )
        } == 0,
        "cannot exclusively own Windows DNS socket (code {})",
        unsafe { WSAGetLastError() }
    );
    let mut value = 0i32;
    let mut length = std::mem::size_of::<i32>() as i32;
    ensure!(
        unsafe {
            getsockopt(
                socket.as_raw_socket() as _,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&mut value as *mut i32).cast(),
                &mut length,
            )
        } == 0
            && length == std::mem::size_of::<i32>() as i32
            && value != 0,
        "Windows DNS exclusive socket policy was not acknowledged"
    );
    Ok(socket)
}
pub(super) fn bind(address: SocketAddrV4) -> Result<(UdpSocket, TcpListener)> {
    let udp = exclusive(Type::DGRAM, Protocol::UDP)?;
    udp.bind(&SocketAddr::V4(address).into())
        .context("cannot exclusively bind Windows DNS UDP endpoint")?;
    let endpoint = udp
        .local_addr()?
        .as_socket()
        .context("invalid Windows DNS endpoint")?;
    let tcp = exclusive(Type::STREAM, Protocol::TCP)?;
    // Failure drops UDP before any NRPT registration can be performed. Never
    // switch on reuse to work around foreign listeners or TCP TIME_WAIT.
    tcp.bind(&endpoint.into())
        .context("cannot exclusively bind Windows DNS TCP endpoint")?;
    tcp.listen(128)?;
    udp.set_nonblocking(true)?;
    tcp.set_nonblocking(true)?;
    Ok((
        UdpSocket::from_std(udp.into())?,
        TcpListener::from_std(tcp.into())?,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn permitted() -> Result<()> {
        ensure!(
            std::env::var("PORTHUB_TEST_DISPOSABLE_WINDOWS_DNS").as_deref() == Ok("1"),
            "requires explicit disposable Windows DNS test opt-in"
        );
        Ok(())
    }
    fn candidate() -> Result<(UdpSocket, TcpListener)> {
        let mut last = None;
        for _ in 0..32 {
            match bind(SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0)) {
                Ok(pair) => return Ok(pair),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap())
    }
    #[tokio::test]
    #[ignore = "native disposable Windows sockets only; no NRPT/device/configuration writes"]
    async fn native_same_account_reuse_cannot_bind_dns_endpoint() -> Result<()> {
        permitted()?;
        let (udp, _tcp) = candidate()?;
        let endpoint = udp.local_addr()?;
        for (kind, protocol) in [(Type::DGRAM, Protocol::UDP), (Type::STREAM, Protocol::TCP)] {
            let attacker = Socket::new(Domain::IPV4, kind, Some(protocol))?;
            attacker.set_reuse_address(true)?;
            ensure!(
                attacker.bind(&endpoint.into()).is_err(),
                "same-account SO_REUSEADDR took over owned DNS endpoint"
            );
        }
        Ok(())
    }
    #[tokio::test]
    #[ignore = "native disposable Windows sockets only; no NRPT/device/configuration writes"]
    async fn native_foreign_udp_or_tcp_listener_prevents_dns_bind_without_takeover() -> Result<()> {
        permitted()?;
        let foreign = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = foreign.local_addr()?;
        let SocketAddr::V4(address) = endpoint else {
            unreachable!()
        };
        ensure!(bind(address).is_err(), "foreign UDP listener was reused");
        ensure!(
            foreign.local_addr()? == endpoint,
            "foreign UDP listener changed"
        );
        drop(foreign);
        let foreign = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let endpoint = foreign.local_addr()?;
        let SocketAddr::V4(address) = endpoint else {
            unreachable!()
        };
        ensure!(bind(address).is_err(), "foreign TCP listener was reused");
        ensure!(
            foreign.local_addr()? == endpoint,
            "foreign TCP listener changed"
        );
        // A failed TCP half must not leak its just-created exclusive UDP half.
        let udp = exclusive(Type::DGRAM, Protocol::UDP)?;
        udp.bind(&endpoint.into())?;
        Ok(())
    }
}
