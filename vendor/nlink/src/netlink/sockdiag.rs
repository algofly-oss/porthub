//! Socket diagnostics implementation for `Connection<SockDiag>`.
//!
//! This module provides methods for querying socket information via the
//! NETLINK_SOCK_DIAG protocol, integrated into the Connection pattern.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, SockDiag};
//! use nlink::sockdiag::{SocketFilter, TcpState};
//!
//! let conn = Connection::<SockDiag>::new()?;
//!
//! // Query all TCP sockets
//! let sockets = conn.query_tcp().await?;
//!
//! // Query with filter
//! let filter = SocketFilter::tcp()
//!     .listening()
//!     .with_tcp_info()
//!     .build();
//! let sockets = conn.query(&filter).await?;
//! # Ok(())
//! # }
//! ```

use std::net::{IpAddr, SocketAddr};

use super::{connection::Connection, error::Result, protocol::SockDiag};
// Re-export sockdiag types that are needed for the API
pub use crate::sockdiag::filter::{
    FilterKind, InetFilter, NetlinkFilter, PacketFilter, SocketFilter, UnixFilter,
};
pub use crate::sockdiag::{
    socket::{InetSocket, SocketInfo, UnixSocket, UnixType},
    types::{
        AddressFamily, BbrInfo, CcInfo, DctcpInfo, MemInfo, Protocol as InetProtocol, SocketState,
        SocketSummary, TcpInfo, TcpState, Timer, VegasInfo,
    },
};

// Netlink constants
use super::dump_frame::done_result;

const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// Socket diagnostics constants
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;
const TCPDIAG_GETSOCK: u16 = 18;
const NLM_F_ACK: u16 = 0x04;

// Inet diag extensions
/// `INET_DIAG_REQ_PROTOCOL` — a **request**-side attribute (a separate
/// namespace from the response attributes below, which is why the id collides
/// with `INET_DIAG_VEGASINFO`). Carries the protocol as a `u32` and overrides
/// `inet_diag_req_v2.sdiag_protocol`, which is only a `u8` (#225).
const INET_DIAG_REQ_PROTOCOL: u16 = 3;

const INET_DIAG_MEMINFO: u16 = 1;
const INET_DIAG_INFO: u16 = 2;
const INET_DIAG_VEGASINFO: u16 = 3;
const INET_DIAG_CONG: u16 = 4;
const INET_DIAG_TOS: u16 = 5;
const INET_DIAG_TCLASS: u16 = 6;
const INET_DIAG_SKMEMINFO: u16 = 7;
const INET_DIAG_SHUTDOWN: u16 = 8;
// DCTCPINFO/BBRINFO are response-only attribute IDs above the 8-bit
// idiag_ext field; all CC-info structs are requested via the
// VEGASINFO extension bit (the kernel then calls the CC module's
// get_info, which picks its own response attr).
const INET_DIAG_DCTCPINFO: u16 = 9;
const INET_DIAG_BBRINFO: u16 = 16;
const INET_DIAG_MARK: u16 = 15;
const INET_DIAG_CGROUP_ID: u16 = 21;
const INET_DIAG_SKV6ONLY: u16 = 11;

// Unix diag attributes
const UNIX_DIAG_NAME: u16 = 0;
const UNIX_DIAG_VFS: u16 = 1;
const UNIX_DIAG_PEER: u16 = 2;
const UNIX_DIAG_ICONS: u16 = 3;
const UNIX_DIAG_RQLEN: u16 = 4;
const UNIX_DIAG_MEMINFO: u16 = 5;
const UNIX_DIAG_SHUTDOWN: u16 = 6;
const UNIX_DIAG_UID: u16 = 7;

// Netlink diag show flags
const NDIAG_SHOW_MEMINFO: u32 = 0x01;
const NDIAG_SHOW_GROUPS: u32 = 0x02;

// Netlink diag attributes
const NETLINK_DIAG_MEMINFO: u16 = 0;
const NETLINK_DIAG_GROUPS: u16 = 1;

#[nlink_macros::send_futures]
impl Connection<SockDiag> {
    /// Query sockets matching the given filter.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, SockDiag};
    /// use nlink::sockdiag::SocketFilter;
    ///
    /// let conn = Connection::<SockDiag>::new()?;
    /// let filter = SocketFilter::tcp().listening().build();
    /// let sockets = conn.query(&filter).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query(&self, filter: &SocketFilter) -> Result<Vec<SocketInfo>> {
        match &filter.kind {
            FilterKind::Inet(f) => self.query_inet(f).await,
            FilterKind::Unix(f) => self.query_unix(f).await,
            FilterKind::Netlink(f) => self.query_netlink(f).await,
            FilterKind::Packet(f) => self.query_packet(f).await,
        }
    }

    /// Query TCP sockets with default filter.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, SockDiag};
    ///
    /// let conn = Connection::<SockDiag>::new()?;
    /// let sockets = conn.query_tcp().await?;
    /// for sock in sockets {
    ///     println!("{} -> {}", sock.local, sock.remote);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query_tcp(&self) -> Result<Vec<InetSocket>> {
        let filter = InetFilter {
            protocol: InetProtocol::Tcp,
            ..Default::default()
        };
        self.query_inet_typed(&filter).await
    }

    /// Query UDP sockets with default filter.
    pub async fn query_udp(&self) -> Result<Vec<InetSocket>> {
        let filter = InetFilter {
            protocol: InetProtocol::Udp,
            ..Default::default()
        };
        self.query_inet_typed(&filter).await
    }

    /// Query Unix sockets with default filter.
    pub async fn query_unix_sockets(&self) -> Result<Vec<UnixSocket>> {
        let filter = UnixFilter::default();
        self.query_unix_typed(&filter).await
    }

    /// Query Netlink sockets with default filter.
    pub async fn query_netlink_sockets(
        &self,
    ) -> Result<Vec<crate::sockdiag::socket::NetlinkSocket>> {
        let filter = NetlinkFilter::default();
        self.query_netlink_typed(&filter).await
    }

    /// Query `AF_PACKET` sockets (the kind `ss -0`/`ss --packet`
    /// lists) with default options (info + meminfo + fanout).
    pub async fn query_packet_sockets(&self) -> Result<Vec<crate::sockdiag::socket::PacketSocket>> {
        let filter = PacketFilter {
            show_meminfo: true,
            show_info: true,
            show_fanout: true,
        };
        Ok(self
            .query_packet(&filter)
            .await?
            .into_iter()
            .filter_map(|s| match s {
                SocketInfo::Packet(p) => Some(p),
                _ => None,
            })
            .collect())
    }

    /// Get aggregated socket statistics across all families.
    ///
    /// Queries TCP, UDP, raw, and Unix sockets and aggregates the counts
    /// by state. This is equivalent to `ss -s`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, SockDiag};
    ///
    /// let conn = Connection::<SockDiag>::new()?;
    /// let summary = conn.socket_summary().await?;
    /// println!("{}", summary);
    /// // Total: 234
    /// // TCP:   45 (estab 23, closed 12, orphaned 0, timewait 8)
    /// // UDP:   12
    /// // RAW:   2
    /// // UNIX:  175
    /// # Ok(())
    /// # }
    /// ```
    pub async fn socket_summary(&self) -> Result<SocketSummary> {
        use crate::sockdiag::types::{SocketSummary, TcpSummary};

        let tcp_filter = InetFilter {
            protocol: InetProtocol::Tcp,
            states: TcpState::all_mask(),
            ..Default::default()
        };
        let tcp_sockets = self.query_inet_typed(&tcp_filter).await?;

        let udp_filter = InetFilter {
            protocol: InetProtocol::Udp,
            ..Default::default()
        };
        let udp_sockets = self.query_inet_typed(&udp_filter).await?;

        let raw_filter = InetFilter {
            protocol: InetProtocol::Raw,
            ..Default::default()
        };
        let raw_sockets = self.query_inet_typed(&raw_filter).await.unwrap_or_default();

        let unix_sockets = self.query_unix_sockets().await?;

        let mut tcp = TcpSummary {
            total: tcp_sockets.len() as u32,
            ..Default::default()
        };

        for sock in &tcp_sockets {
            match sock.state {
                SocketState::Tcp(TcpState::Established) => tcp.established += 1,
                SocketState::Tcp(TcpState::SynSent) => tcp.syn_sent += 1,
                SocketState::Tcp(TcpState::SynRecv) => tcp.syn_recv += 1,
                SocketState::Tcp(TcpState::FinWait1) => tcp.fin_wait1 += 1,
                SocketState::Tcp(TcpState::FinWait2) => tcp.fin_wait2 += 1,
                SocketState::Tcp(TcpState::TimeWait) => tcp.time_wait += 1,
                SocketState::Tcp(TcpState::Close) => tcp.close += 1,
                SocketState::Tcp(TcpState::CloseWait) => tcp.close_wait += 1,
                SocketState::Tcp(TcpState::LastAck) => tcp.last_ack += 1,
                SocketState::Tcp(TcpState::Listen) => tcp.listen += 1,
                SocketState::Tcp(TcpState::Closing) => tcp.closing += 1,
                _ => {}
            }
        }

        Ok(SocketSummary {
            tcp,
            udp: udp_sockets.len() as u32,
            raw: raw_sockets.len() as u32,
            unix: unix_sockets.len() as u32,
        })
    }

    /// Force-close a TCP socket by sending `SOCK_DESTROY`.
    ///
    /// The kernel sends a RST to the remote peer. Requires `CAP_NET_ADMIN`
    /// and Linux 4.9+. Only TCP sockets can be destroyed.
    ///
    /// # Errors
    ///
    /// Returns `Error::Kernel` with `EPERM` if insufficient privileges.
    /// Returns `Error::Kernel` with `EOPNOTSUPP` if the socket type doesn't
    /// support destruction.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::netlink::SockDiag>::new()?;
    /// let sockets = conn.query_tcp().await?;
    /// for sock in &sockets {
    ///     if sock.remote.port() == 8080 {
    ///         conn.destroy_tcp_socket(sock).await?;
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn destroy_tcp_socket(&self, socket: &InetSocket) -> Result<()> {
        let seq = self.socket().next_seq();
        let mut session = self.recv_session(seq).await?;
        let pid = self.socket().pid();

        let mut buf = Vec::with_capacity(128);

        // Netlink header (16 bytes)
        buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len (filled later)
        buf.extend_from_slice(&SOCK_DESTROY.to_ne_bytes()); // nlmsg_type
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes()); // nlmsg_flags
        buf.extend_from_slice(&seq.to_ne_bytes()); // nlmsg_seq
        buf.extend_from_slice(&pid.to_ne_bytes()); // nlmsg_pid

        // inet_diag_req_v2 (56 bytes)
        buf.push(socket.family as u8); // sdiag_family
        buf.push(socket.protocol.number()); // sdiag_protocol
        buf.push(0); // idiag_ext
        buf.push(0); // pad
        buf.extend_from_slice(&0u32.to_ne_bytes()); // idiag_states (unused for destroy)

        // inet_diag_sockid (48 bytes)
        buf.extend_from_slice(&socket.local.port().to_be_bytes()); // idiag_sport
        buf.extend_from_slice(&socket.remote.port().to_be_bytes()); // idiag_dport

        // Source address (16 bytes, IPv4 in first 4 bytes)
        match socket.local.ip() {
            std::net::IpAddr::V4(v4) => {
                buf.extend_from_slice(&v4.octets());
                buf.extend_from_slice(&[0u8; 12]);
            }
            std::net::IpAddr::V6(v6) => {
                buf.extend_from_slice(&v6.octets());
            }
        }

        // Destination address (16 bytes)
        match socket.remote.ip() {
            std::net::IpAddr::V4(v4) => {
                buf.extend_from_slice(&v4.octets());
                buf.extend_from_slice(&[0u8; 12]);
            }
            std::net::IpAddr::V6(v6) => {
                buf.extend_from_slice(&v6.octets());
            }
        }

        buf.extend_from_slice(&socket.interface.to_ne_bytes()); // idiag_if
        buf.extend_from_slice(&socket.cookie.to_ne_bytes()); // idiag_cookie

        // Update length
        let len = buf.len() as u32;
        buf[0..4].copy_from_slice(&len.to_ne_bytes());

        // Wrapped in with_timeout (Plan 171). Filters by seq so the
        // ACK is matched to the in-flight request even if other
        // queries on the same socket leave stale frames.
        self.with_timeout(async move {
            // Send request inside the timeout window so the whole
            // send+ack budget is bounded together.
            self.socket().send(&buf).await?;

            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;
                if data.len() < 16 {
                    return Err(crate::netlink::Error::invalid_message(
                        "response too short",
                    ));
                }
                let resp_seq =
                    u32::from_ne_bytes([data[8], data[9], data[10], data[11]]);
                if resp_seq != seq {
                    continue;
                }
                let msg_type = u16::from_ne_bytes([data[4], data[5]]);
                if msg_type == NLMSG_ERROR {
                    if data.len() >= 20 {
                        let errno =
                            i32::from_ne_bytes([data[16], data[17], data[18], data[19]]);
                        if errno != 0 {
                            // Route through the `from_errno_with_context_ext_ack`
                            // factory so the stored errno is the
                            // canonical positive POSIX value (Plan 187).
                            return Err(
                                crate::netlink::Error::from_errno_with_context_ext_ack(
                                    errno,
                                    "SOCK_DESTROY",
                                    None,
                                    None,
                                ),
                            );
                        }
                    }
                    return Ok(());
                }
                // Non-error response with matching seq is unusual for
                // SOCK_DESTROY but treat as success ACK semantics.
                return Ok(());
            }
        })
        .await
    }

    /// Destroy all TCP sockets matching the given filter.
    ///
    /// Queries sockets matching the filter, then destroys each one.
    /// Returns a `DestroyResult` with the count of destroyed sockets and any errors.
    /// Requires `CAP_NET_ADMIN`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::Connection;
    /// # use nlink::netlink::SockDiag;
    /// use nlink::sockdiag::{SocketFilter, TcpState};
    ///
    /// let conn = Connection::<SockDiag>::new()?;
    /// let filter = SocketFilter::tcp()
    ///     .states(&[TcpState::TimeWait])
    ///     .build_inet();
    /// let result = conn.destroy_matching(&filter).await?;
    /// println!("Destroyed {} sockets", result.destroyed);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn destroy_matching(
        &self,
        filter: &InetFilter,
    ) -> Result<crate::sockdiag::types::DestroyResult> {
        let sockets = self.query_inet_typed(filter).await?;
        let mut destroyed = 0u32;
        let mut errors = Vec::new();

        for sock in &sockets {
            match self.destroy_tcp_socket(sock).await {
                Ok(()) => destroyed += 1,
                Err(e) => errors.push(crate::sockdiag::types::DestroyError {
                    socket: sock.local,
                    error: e,
                }),
            }
        }

        Ok(crate::sockdiag::types::DestroyResult { destroyed, errors })
    }

    async fn query_inet(&self, filter: &InetFilter) -> Result<Vec<SocketInfo>> {
        let sockets = self.query_inet_typed(filter).await?;
        Ok(sockets
            .into_iter()
            .map(|s| SocketInfo::Inet(Box::new(s)))
            .collect())
    }

    async fn query_inet_typed(&self, filter: &InetFilter) -> Result<Vec<InetSocket>> {
        let mut results = Vec::new();

        // Query IPv4 if not filtering to IPv6 only
        if filter.family.is_none() || filter.family == Some(AddressFamily::Inet) {
            let sockets = self.query_inet_family(filter, AddressFamily::Inet).await?;
            results.extend(sockets);
        }

        // Query IPv6 if not filtering to IPv4 only
        if filter.family.is_none() || filter.family == Some(AddressFamily::Inet6) {
            let sockets = self.query_inet_family(filter, AddressFamily::Inet6).await?;
            results.extend(sockets);
        }

        Ok(results)
    }

    async fn query_inet_family(
        &self,
        filter: &InetFilter,
        family: AddressFamily,
    ) -> Result<Vec<InetSocket>> {
        // Kernel-side lowering (#163): build ONE effective expression
        // from the filter's exact ports plus the optional full
        // FilterExpr, and compile it once. Composition MUST happen at
        // the expression level — concatenating two independently
        // compiled programs is invalid (the first one's reject
        // overshoot would land mid-instruction in the second).
        //
        // `local_addr` / `remote_addr` join the expression here too (#223):
        // they used to be read by nothing at all, so
        // `SocketFilter::tcp().local_addr(..)` returned every TCP socket on
        // the box. As `Src`/`Dst` conjuncts they lower to the same
        // `S_COND`/`D_COND` the expression grammar already uses.
        let effective_expr = {
            use crate::sockdiag::expr::{Comparison, FilterExpr};
            let mut expr: Option<FilterExpr> = filter.expr.clone();
            let and = |leaf: FilterExpr, expr: &mut Option<FilterExpr>| {
                *expr = Some(match expr.take() {
                    Some(e) => FilterExpr::And(Box::new(e), Box::new(leaf)),
                    None => leaf,
                });
            };
            if let Some(p) = filter.local_port {
                and(FilterExpr::Sport(Comparison::Eq, p), &mut expr);
            }
            if let Some(p) = filter.remote_port {
                and(FilterExpr::Dport(Comparison::Eq, p), &mut expr);
            }
            if let Some(a) = filter.local_addr {
                and(FilterExpr::Src(a, full_prefix(&a)), &mut expr);
            }
            if let Some(a) = filter.remote_addr {
                and(FilterExpr::Dst(a, full_prefix(&a)), &mut expr);
            }
            expr
        };
        let compiled = effective_expr
            .as_ref()
            .map(crate::sockdiag::bytecode::compile_filter)
            .unwrap_or_default();
        // Client-side backstop: needed whenever the kernel-side lowering
        // over-approximates.
        //
        // It is built from the **effective** expression, not from
        // `filter.expr`: `exact` describes what was pushed down, which now
        // includes the port and address conjuncts, so backstopping only
        // `filter.expr` would leave those unenforced whenever the lowering was
        // inexact for some other reason (#223).
        let backstop = if compiled.exact {
            None
        } else {
            effective_expr.clone()
        };

        // Plan 208 Phase 1+2 — wrap in with_timeout, seq filter,
        // NLM_F_DUMP_INTR detection.
        self.with_timeout(async move {
            let seq = self.socket().next_seq();
            let mut session = self.recv_session_dump(seq).await?;
            let pid = self.socket().pid();

            let mut buf = Vec::with_capacity(256);
            let msg_type = SOCK_DIAG_BY_FAMILY;

            buf.extend_from_slice(&0u32.to_ne_bytes());
            buf.extend_from_slice(&msg_type.to_ne_bytes());
            buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
            buf.extend_from_slice(&seq.to_ne_bytes());
            buf.extend_from_slice(&pid.to_ne_bytes());

            buf.push(family as u8);
            buf.push(filter.protocol.number());
            buf.push(filter.extensions);
            buf.push(0);
            // Pure-state conjuncts of the expression hoist into the
            // header's states bitmask (there is no state opcode).
            let states = filter.states & compiled.states.unwrap_or(u32::MAX);
            buf.extend_from_slice(&states.to_ne_bytes());

            buf.extend_from_slice(&0u16.to_be_bytes());
            buf.extend_from_slice(&0u16.to_be_bytes());
            buf.extend_from_slice(&[0u8; 16]);
            buf.extend_from_slice(&[0u8; 16]);
            buf.extend_from_slice(&0u32.to_ne_bytes());
            buf.extend_from_slice(&[0u8; 8]);

            // INET_DIAG_REQ_PROTOCOL (#225) — `sdiag_protocol` above is a u8,
            // and IPPROTO_MPTCP is 262. Without this attribute the kernel
            // dispatches on the truncated byte (262 & 0xff == 6 == TCP) and
            // `SocketFilter::mptcp()` silently becomes a TCP dump whose every
            // result is stamped `Protocol::Mptcp`.
            if !filter.protocol.fits_in_u8() {
                buf.extend_from_slice(&8u16.to_ne_bytes()); // nla_len
                buf.extend_from_slice(&INET_DIAG_REQ_PROTOCOL.to_ne_bytes());
                buf.extend_from_slice(&filter.protocol.number_u32().to_ne_bytes());
            }

            // Optional INET_DIAG_REQ_BYTECODE attribute — run the
            // compiled program as a kernel-side pre-filter so far
            // fewer sockets cross into userspace. A malformed program
            // is rejected by the kernel's bc-audit with EINVAL (loud);
            // the client-side backstop keeps correctness whenever the
            // lowering was inexact.
            if let Some(code) = &compiled.bytecode {
                let attr_len = (4 + code.len()) as u16;
                buf.extend_from_slice(&attr_len.to_ne_bytes());
                buf.extend_from_slice(
                    &crate::sockdiag::bytecode::INET_DIAG_REQ_BYTECODE.to_ne_bytes(),
                );
                buf.extend_from_slice(code);
                // Pad the attribute to a 4-byte boundary.
                let pad = (4 - (code.len() % 4)) % 4;
                buf.extend(std::iter::repeat_n(0u8, pad));
            }

            let len = buf.len() as u32;
            buf[0..4].copy_from_slice(&len.to_ne_bytes());

            self.socket().send(&buf).await?;

            let mut sockets = Vec::new();

            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;

                let mut offset = 0;
                while offset + 16 <= data.len() {
                    let nlmsg_len = u32::from_ne_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]) as usize;

                    let nlmsg_type = u16::from_ne_bytes([data[offset + 4], data[offset + 5]]);
                    let nlmsg_flags = u16::from_ne_bytes([data[offset + 6], data[offset + 7]]);
                    let nlmsg_seq = u32::from_ne_bytes([
                        data[offset + 8],
                        data[offset + 9],
                        data[offset + 10],
                        data[offset + 11],
                    ]);

                    if nlmsg_len < 16 || offset + nlmsg_len > data.len() {
                        break;
                    }
                    if nlmsg_seq != seq {
                        offset += (nlmsg_len + 3) & !3;
                        continue;
                    }
                    if nlmsg_flags & 0x10 != 0 {
                        return Err(crate::netlink::Error::dump_interrupted());
                    }

                    match nlmsg_type {
                        // The dump's result code lives in the DONE
                        // payload, and this returned `Ok(sockets)`
                        // without looking: a `SOCK_DIAG_BY_FAMILY`
                        // query the kernel refused came back as
                        // "no sockets found" (#267). Measured: DONE
                        // with payload -2 (-ENOENT).
                        NLMSG_DONE => {
                            done_result(&data[offset + 16..offset + nlmsg_len])?;
                            return Ok(sockets);
                        }
                        NLMSG_ERROR if nlmsg_len >= 20 => {
                            let errno = i32::from_ne_bytes([
                                data[offset + 16],
                                data[offset + 17],
                                data[offset + 18],
                                data[offset + 19],
                            ]);
                            if errno != 0 {
                                return Err(super::error::Error::from_errno_with_context(
                                    errno,
                                    "sock_diag_dump(inet)",
                                ));
                            }
                        }
                        SOCK_DIAG_BY_FAMILY | TCPDIAG_GETSOCK => {
                            if let Some(sock) = parse_inet_msg(
                                &data[offset..offset + nlmsg_len],
                                filter.protocol,
                            ) {
                                // Backstop for inexact kernel-side
                                // lowering (#163), then the scalar filters
                                // that have no bytecode form (#223).
                                if backstop.as_ref().is_none_or(|e| e.matches(&sock))
                                    && matches_scalar_filters(&sock, filter)
                                {
                                    sockets.push(sock);
                                }
                            }
                        }
                        _ => {}
                    }

                    offset += (nlmsg_len + 3) & !3;
                }
            }
        })
        .await
    }

    async fn query_unix(&self, filter: &UnixFilter) -> Result<Vec<SocketInfo>> {
        let sockets = self.query_unix_typed(filter).await?;
        Ok(sockets.into_iter().map(SocketInfo::Unix).collect())
    }

    async fn query_unix_typed(&self, filter: &UnixFilter) -> Result<Vec<UnixSocket>> {
        // Plan 208 Phase 1+2 — wrap in with_timeout, seq filter,
        // NLM_F_DUMP_INTR detection.
        self.with_timeout(async move {
            let seq = self.socket().next_seq();
            let mut session = self.recv_session_dump(seq).await?;
            let pid = self.socket().pid();

            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&0u32.to_ne_bytes());
            buf.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
            buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
            buf.extend_from_slice(&seq.to_ne_bytes());
            buf.extend_from_slice(&pid.to_ne_bytes());

            buf.push(libc::AF_UNIX as u8);
            buf.push(0);
            buf.extend_from_slice(&0u16.to_ne_bytes());
            buf.extend_from_slice(&filter.states.to_ne_bytes());
            buf.extend_from_slice(&filter.inode.unwrap_or(0).to_ne_bytes());
            buf.extend_from_slice(&filter.show.to_ne_bytes());
            buf.extend_from_slice(&[0u8; 8]);

            let len = buf.len() as u32;
            buf[0..4].copy_from_slice(&len.to_ne_bytes());

            self.socket().send(&buf).await?;

            let mut sockets = Vec::new();

            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;

                let mut offset = 0;
                while offset + 16 <= data.len() {
                    let nlmsg_len = u32::from_ne_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]) as usize;

                    let nlmsg_type = u16::from_ne_bytes([data[offset + 4], data[offset + 5]]);
                    let nlmsg_flags = u16::from_ne_bytes([data[offset + 6], data[offset + 7]]);
                    let nlmsg_seq = u32::from_ne_bytes([
                        data[offset + 8],
                        data[offset + 9],
                        data[offset + 10],
                        data[offset + 11],
                    ]);

                    if nlmsg_len < 16 || offset + nlmsg_len > data.len() {
                        break;
                    }
                    if nlmsg_seq != seq {
                        offset += (nlmsg_len + 3) & !3;
                        continue;
                    }
                    if nlmsg_flags & 0x10 != 0 {
                        return Err(crate::netlink::Error::dump_interrupted());
                    }

                    match nlmsg_type {
                        // The dump's result code lives in the DONE
                        // payload, and this returned `Ok(sockets)`
                        // without looking: a `SOCK_DIAG_BY_FAMILY`
                        // query the kernel refused came back as
                        // "no sockets found" (#267). Measured: DONE
                        // with payload -2 (-ENOENT).
                        NLMSG_DONE => {
                            done_result(&data[offset + 16..offset + nlmsg_len])?;
                            return Ok(sockets);
                        }
                        NLMSG_ERROR if nlmsg_len >= 20 => {
                            let errno = i32::from_ne_bytes([
                                data[offset + 16],
                                data[offset + 17],
                                data[offset + 18],
                                data[offset + 19],
                            ]);
                            if errno != 0 {
                                return Err(super::error::Error::from_errno_with_context(
                                    errno,
                                    "sock_diag_dump(unix)",
                                ));
                            }
                        }
                        SOCK_DIAG_BY_FAMILY => {
                            if let Some(sock) = parse_unix_msg(&data[offset..offset + nlmsg_len])
                            {
                                // socket_types / path_pattern were read by
                                // nothing at all, so `.unix().stream().path(..)`
                                // returned every unix socket of every type
                                // (#223). The unix diag request carries no
                                // filter for either, so both are client-side.
                                if matches_unix_filter(&sock, filter) {
                                    sockets.push(sock);
                                }
                            }
                        }
                        _ => {}
                    }

                    offset += (nlmsg_len + 3) & !3;
                }
            }
        })
        .await
    }

    async fn query_netlink(&self, filter: &NetlinkFilter) -> Result<Vec<SocketInfo>> {
        let sockets = self.query_netlink_typed(filter).await?;
        Ok(sockets.into_iter().map(SocketInfo::Netlink).collect())
    }

    async fn query_netlink_typed(
        &self,
        filter: &NetlinkFilter,
    ) -> Result<Vec<crate::sockdiag::socket::NetlinkSocket>> {
        // Plan 208 Phase 1+2 — wrap in with_timeout, seq filter,
        // NLM_F_DUMP_INTR detection.
        self.with_timeout(async move {
            let seq = self.socket().next_seq();
            let mut session = self.recv_session_dump(seq).await?;
            let pid = self.socket().pid();

            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&0u32.to_ne_bytes());
            buf.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
            buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
            buf.extend_from_slice(&seq.to_ne_bytes());
            buf.extend_from_slice(&pid.to_ne_bytes());

            buf.push(libc::AF_NETLINK as u8);
            buf.push(filter.protocol.unwrap_or(0xff));
            buf.extend_from_slice(&0u16.to_ne_bytes());

            buf.extend_from_slice(&0u32.to_ne_bytes());
            let mut show: u32 = 0;
            if filter.show_meminfo {
                show |= NDIAG_SHOW_MEMINFO;
            }
            if filter.show_groups {
                show |= NDIAG_SHOW_GROUPS;
            }
            buf.extend_from_slice(&show.to_ne_bytes());
            buf.extend_from_slice(&[0u8; 8]);

            let len = buf.len() as u32;
            buf[0..4].copy_from_slice(&len.to_ne_bytes());

            self.socket().send(&buf).await?;

            let mut sockets = Vec::new();

            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;

                let mut offset = 0;
                while offset + 16 <= data.len() {
                    let nlmsg_len = u32::from_ne_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]) as usize;

                    let nlmsg_type = u16::from_ne_bytes([data[offset + 4], data[offset + 5]]);
                    let nlmsg_flags = u16::from_ne_bytes([data[offset + 6], data[offset + 7]]);
                    let nlmsg_seq = u32::from_ne_bytes([
                        data[offset + 8],
                        data[offset + 9],
                        data[offset + 10],
                        data[offset + 11],
                    ]);

                    if nlmsg_len < 16 || offset + nlmsg_len > data.len() {
                        break;
                    }
                    if nlmsg_seq != seq {
                        offset += (nlmsg_len + 3) & !3;
                        continue;
                    }
                    if nlmsg_flags & 0x10 != 0 {
                        return Err(crate::netlink::Error::dump_interrupted());
                    }

                    match nlmsg_type {
                        // The dump's result code lives in the DONE
                        // payload, and this returned `Ok(sockets)`
                        // without looking: a `SOCK_DIAG_BY_FAMILY`
                        // query the kernel refused came back as
                        // "no sockets found" (#267). Measured: DONE
                        // with payload -2 (-ENOENT).
                        NLMSG_DONE => {
                            done_result(&data[offset + 16..offset + nlmsg_len])?;
                            return Ok(sockets);
                        }
                        NLMSG_ERROR if nlmsg_len >= 20 => {
                            let errno = i32::from_ne_bytes([
                                data[offset + 16],
                                data[offset + 17],
                                data[offset + 18],
                                data[offset + 19],
                            ]);
                            if errno != 0 {
                                return Err(super::error::Error::from_errno_with_context(
                                    errno,
                                    "sock_diag_dump(netlink)",
                                ));
                            }
                        }
                        SOCK_DIAG_BY_FAMILY => {
                            if let Some(sock) =
                                parse_netlink_msg(&data[offset..offset + nlmsg_len], filter)
                            {
                                sockets.push(sock);
                            }
                        }
                        _ => {}
                    }

                    offset += (nlmsg_len + 3) & !3;
                }
            }
        })
        .await
    }

    async fn query_packet(&self, filter: &PacketFilter) -> Result<Vec<SocketInfo>> {
        self.with_timeout(async move {
            let seq = self.socket().next_seq();
            let mut session = self.recv_session_dump(seq).await?;
            let pid = self.socket().pid();

            // struct packet_diag_req {
            //   __u8 sdiag_family; __u8 sdiag_protocol; __u16 pad;
            //   __u32 pdiag_ino; __u32 pdiag_show; __u32 pdiag_cookie[2];
            // }
            let mut buf = Vec::with_capacity(36);
            buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_len placeholder
            buf.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
            buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
            buf.extend_from_slice(&seq.to_ne_bytes());
            buf.extend_from_slice(&pid.to_ne_bytes());

            buf.push(libc::AF_PACKET as u8); // sdiag_family
            buf.push(0); // sdiag_protocol (0 = all)
            buf.extend_from_slice(&0u16.to_ne_bytes()); // pad
            buf.extend_from_slice(&0u32.to_ne_bytes()); // pdiag_ino (0 = all)

            // pdiag_show flags.
            const PACKET_SHOW_INFO: u32 = 1;
            const PACKET_SHOW_FANOUT: u32 = 8;
            const PACKET_SHOW_MEMINFO: u32 = 16;
            let mut show = 0u32;
            if filter.show_info {
                show |= PACKET_SHOW_INFO;
            }
            if filter.show_fanout {
                show |= PACKET_SHOW_FANOUT;
            }
            if filter.show_meminfo {
                show |= PACKET_SHOW_MEMINFO;
            }
            // Always request INFO so the interface/version fields populate.
            show |= PACKET_SHOW_INFO;
            buf.extend_from_slice(&show.to_ne_bytes());
            buf.extend_from_slice(&[0u8; 8]); // pdiag_cookie

            let len = buf.len() as u32;
            buf[0..4].copy_from_slice(&len.to_ne_bytes());

            self.socket().send(&buf).await?;

            let mut sockets = Vec::new();
            loop {
                let data: Vec<u8> = session.recv_with_timeout(self).await?;

                let mut offset = 0;
                while offset + 16 <= data.len() {
                    let nlmsg_len = u32::from_ne_bytes([
                        data[offset],
                        data[offset + 1],
                        data[offset + 2],
                        data[offset + 3],
                    ]) as usize;
                    let nlmsg_type = u16::from_ne_bytes([data[offset + 4], data[offset + 5]]);
                    let nlmsg_flags = u16::from_ne_bytes([data[offset + 6], data[offset + 7]]);
                    let nlmsg_seq = u32::from_ne_bytes([
                        data[offset + 8],
                        data[offset + 9],
                        data[offset + 10],
                        data[offset + 11],
                    ]);

                    if nlmsg_len < 16 || offset + nlmsg_len > data.len() {
                        break;
                    }
                    if nlmsg_seq != seq {
                        offset += (nlmsg_len + 3) & !3;
                        continue;
                    }
                    if nlmsg_flags & 0x10 != 0 {
                        return Err(crate::netlink::Error::dump_interrupted());
                    }

                    match nlmsg_type {
                        // The dump's result code lives in the DONE
                        // payload, and this returned `Ok(sockets)`
                        // without looking: a `SOCK_DIAG_BY_FAMILY`
                        // query the kernel refused came back as
                        // "no sockets found" (#267). Measured: DONE
                        // with payload -2 (-ENOENT).
                        NLMSG_DONE => {
                            done_result(&data[offset + 16..offset + nlmsg_len])?;
                            return Ok(sockets);
                        }
                        NLMSG_ERROR if nlmsg_len >= 20 => {
                            let errno = i32::from_ne_bytes([
                                data[offset + 16],
                                data[offset + 17],
                                data[offset + 18],
                                data[offset + 19],
                            ]);
                            if errno != 0 {
                                return Err(super::error::Error::from_errno_with_context(
                                    errno,
                                    "packet_diag",
                                ));
                            }
                        }
                        SOCK_DIAG_BY_FAMILY => {
                            if let Some(sock) = parse_packet_msg(&data[offset..offset + nlmsg_len]) {
                                sockets.push(SocketInfo::Packet(sock));
                            }
                        }
                        _ => {}
                    }

                    offset += (nlmsg_len + 3) & !3;
                }
            }
        })
        .await
    }
}

/// Parse a single `packet_diag_msg` (+ attributes) into a
/// [`PacketSocket`]. Returns `None` if the buffer is too short or the
/// family is not `AF_PACKET`.
fn parse_packet_msg(data: &[u8]) -> Option<crate::sockdiag::socket::PacketSocket> {
    // struct packet_diag_msg {
    //   __u8 pdiag_family; __u8 pdiag_type; __u16 pdiag_num;
    //   __u32 pdiag_ino; __u32 pdiag_cookie[2];
    // } = 16 bytes, after the 16-byte nlmsghdr.
    if data.len() < 16 + 16 {
        return None;
    }
    let payload = &data[16..];
    if payload[0] != libc::AF_PACKET as u8 {
        return None;
    }

    let socket_type = payload[1];
    let protocol = u16::from_ne_bytes([payload[2], payload[3]]);
    let inode = u32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let cookie = u64::from_ne_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ]);

    let mut sock = crate::sockdiag::socket::PacketSocket {
        socket_type,
        protocol,
        interface: 0,
        inode,
        cookie,
        uid: 0,
        recv_q: None,
        send_q: None,
        fanout: None,
        mem_info: None,
    };

    // PACKET_DIAG_* attribute types.
    const PACKET_DIAG_INFO: u16 = 0;
    const PACKET_DIAG_FANOUT: u16 = 4;
    const PACKET_DIAG_UID: u16 = 5;
    const PACKET_DIAG_MEMINFO: u16 = 6;

    let mut attr_offset = 16 + 16;
    while attr_offset + 4 <= data.len() {
        let attr_len = u16::from_ne_bytes([data[attr_offset], data[attr_offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[attr_offset + 2], data[attr_offset + 3]]);
        if attr_len < 4 || attr_offset + attr_len > data.len() {
            break;
        }
        let attr_data = &data[attr_offset + 4..attr_offset + attr_len];

        match attr_type {
            // struct packet_diag_info { __u32 pdi_index; ... } — the
            // first field is the bound interface index.
            PACKET_DIAG_INFO if attr_data.len() >= 4 => {
                sock.interface =
                    u32::from_ne_bytes([attr_data[0], attr_data[1], attr_data[2], attr_data[3]]);
            }
            PACKET_DIAG_UID if attr_data.len() >= 4 => {
                sock.uid =
                    u32::from_ne_bytes([attr_data[0], attr_data[1], attr_data[2], attr_data[3]]);
            }
            PACKET_DIAG_FANOUT if attr_data.len() >= 4 => {
                sock.fanout = Some(u32::from_ne_bytes([
                    attr_data[0],
                    attr_data[1],
                    attr_data[2],
                    attr_data[3],
                ]));
            }
            // struct sk_meminfo (>= 36 bytes); rmem_alloc / wmem_alloc
            // map to recv_q / send_q like the other socket families.
            PACKET_DIAG_MEMINFO if attr_data.len() >= 36 => {
                sock.recv_q =
                    Some(u32::from_ne_bytes([attr_data[0], attr_data[1], attr_data[2], attr_data[3]]));
                sock.send_q = Some(u32::from_ne_bytes([
                    attr_data[8],
                    attr_data[9],
                    attr_data[10],
                    attr_data[11],
                ]));
            }
            _ => {}
        }

        attr_offset += (attr_len + 3) & !3;
    }

    Some(sock)
}

// Helper functions for parsing

fn parse_ipv4(data: &[u8]) -> std::net::Ipv4Addr {
    if data.len() >= 4 {
        std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3])
    } else {
        std::net::Ipv4Addr::UNSPECIFIED
    }
}

fn parse_ipv6(data: &[u8]) -> std::net::Ipv6Addr {
    if data.len() >= 16 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&data[..16]);
        std::net::Ipv6Addr::from(octets)
    } else {
        std::net::Ipv6Addr::UNSPECIFIED
    }
}

fn parse_port(data: &[u8]) -> u16 {
    if data.len() >= 2 {
        u16::from_be_bytes([data[0], data[1]])
    } else {
        0
    }
}

/// Read a native-endian `u32` at `off`. Callers guard the length.
fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// Decode the `enum sk_meminfo_stats` array — a `u32[9]`.
///
/// The same array is carried by `INET_DIAG_SKMEMINFO`, `UNIX_DIAG_MEMINFO` and
/// `NETLINK_DIAG_MEMINFO`, so all three decode through here. Callers guard
/// `len >= 36`.
fn parse_sk_meminfo(buf: &[u8]) -> MemInfo {
    MemInfo {
        rmem_alloc: u32_at(buf, 0),
        rcvbuf: Some(u32_at(buf, 4)),
        wmem_alloc: u32_at(buf, 8),
        sndbuf: Some(u32_at(buf, 12)),
        fwd_alloc: u32_at(buf, 16),
        wmem_queued: u32_at(buf, 20),
        optmem: Some(u32_at(buf, 24)),
        backlog: Some(u32_at(buf, 28)),
        drops: Some(u32_at(buf, 32)),
    }
}

/// The all-ones prefix for an address family — the prefix length that turns a
/// bare address into an exact match.
fn full_prefix(addr: &std::net::IpAddr) -> u8 {
    match addr {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    }
}

/// The [`UnixFilter`] fields the unix diag request cannot carry, applied
/// client-side (#223).
///
/// `unix_diag_req` has a `udiag_states` mask and an `udiag_ino`, and that is
/// all — there is no type mask and no path filter on the wire. Both builders
/// were therefore silently doing nothing: `.unix().stream().path("/run/foo")`
/// returned every unix socket of every type. Nor does a dump read
/// `udiag_ino`: only the exact lookup does (`unix_diag_get_exact`, which also
/// needs the cookie), so `.inode(n)` returned every socket too (#776).
///
/// `path_pattern` is a substring match, matched against the filesystem path or,
/// for an abstract socket, its `@name`.
fn matches_unix_filter(sock: &UnixSocket, filter: &UnixFilter) -> bool {
    if filter.socket_types & (1 << (sock.socket_type as u32)) == 0 {
        return false;
    }
    if filter.inode.is_some_and(|ino| ino != sock.inode) {
        return false;
    }
    if let Some(pattern) = &filter.path_pattern {
        let hit = sock
            .path
            .as_deref()
            .or(sock.abstract_name.as_deref())
            .is_some_and(|p| p.contains(pattern.as_str()));
        if !hit {
            return false;
        }
    }
    true
}

/// The [`InetFilter`] fields that have no expression form and are applied
/// client-side (#223): interface, mark, cgroup id.
///
/// These three could in principle lower to `DEV_COND` / `MARK_COND` /
/// `CGROUP_COND`, but this module deliberately emits no opcode newer than
/// `D_COND`: a kernel that does not know an opcode fails `inet_diag_bc_audit`
/// with `EINVAL`, which kills the **whole dump** rather than degrading to a
/// superset. `MARK_COND` additionally requires `CAP_NET_ADMIN` for the *audit*
/// to pass, so an unprivileged caller would lose the dump entirely.
///
/// Filtering client-side costs a wider kernel-side result set and nothing else.
///
/// One caveat, inherited from the kernel: `INET_DIAG_MARK` is only emitted to a
/// dumper with `CAP_NET_ADMIN`. Unprivileged, `sock.mark` is `None`, so a mark
/// filter matches nothing — which is the honest answer (the information was
/// withheld), not a silent pass.
fn matches_scalar_filters(sock: &InetSocket, filter: &InetFilter) -> bool {
    if let Some(ifindex) = filter.interface
        && sock.interface != ifindex
    {
        return false;
    }
    if let Some((value, mask)) = filter.mark {
        match sock.mark {
            Some(m) if m & mask == value & mask => {}
            _ => return false,
        }
    }
    if let Some(id) = filter.cgroup_id
        && sock.cgroup_id != Some(id)
    {
        return false;
    }
    true
}

fn parse_inet_msg(data: &[u8], protocol: InetProtocol) -> Option<InetSocket> {
    // Skip netlink header (16 bytes)
    if data.len() < 16 + 72 {
        return None;
    }

    let payload = &data[16..];

    // inet_diag_msg structure
    let family = AddressFamily::from_u8(payload[0])?;
    let state = TcpState::from_u8(payload[1]);
    let timer = payload[2];
    let retrans = payload[3];

    // inet_diag_sockid at offset 4
    let sport = parse_port(&payload[4..6]);
    let dport = parse_port(&payload[6..8]);

    let (src_ip, dst_ip) = match family {
        AddressFamily::Inet => {
            let src = IpAddr::V4(parse_ipv4(&payload[8..12]));
            let dst = IpAddr::V4(parse_ipv4(&payload[24..28]));
            (src, dst)
        }
        AddressFamily::Inet6 => {
            let src = IpAddr::V6(parse_ipv6(&payload[8..24]));
            let dst = IpAddr::V6(parse_ipv6(&payload[24..40]));
            (src, dst)
        }
        _ => return None,
    };

    let interface = u32::from_ne_bytes([payload[40], payload[41], payload[42], payload[43]]);
    let cookie = u64::from_ne_bytes([
        payload[44],
        payload[45],
        payload[46],
        payload[47],
        payload[48],
        payload[49],
        payload[50],
        payload[51],
    ]);

    // After sockid: expires, rqueue, wqueue, uid, inode
    let expires = u32::from_ne_bytes([payload[52], payload[53], payload[54], payload[55]]);
    let rqueue = u32::from_ne_bytes([payload[56], payload[57], payload[58], payload[59]]);
    let wqueue = u32::from_ne_bytes([payload[60], payload[61], payload[62], payload[63]]);
    let uid = u32::from_ne_bytes([payload[64], payload[65], payload[66], payload[67]]);
    let inode = u32::from_ne_bytes([payload[68], payload[69], payload[70], payload[71]]);

    let mut sock = InetSocket {
        family,
        protocol,
        state: SocketState::Tcp(state),
        local: SocketAddr::new(src_ip, sport),
        remote: SocketAddr::new(dst_ip, dport),
        interface,
        cookie,
        timer: Timer::from_raw(timer, expires, retrans),
        recv_q: rqueue,
        send_q: wqueue,
        uid,
        inode,
        refcnt: 0,
        mark: None,
        cgroup_id: None,
        tcp_info: None,
        mem_info: None,
        congestion: None,
        cc_info: None,
        tos: None,
        tclass: None,
        shutdown: None,
        v6only: None,
    };

    // Parse attributes
    let mut attr_offset = 16 + 72;
    while attr_offset + 4 <= data.len() {
        let attr_len = u16::from_ne_bytes([data[attr_offset], data[attr_offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[attr_offset + 2], data[attr_offset + 3]]);

        if attr_len < 4 || attr_offset + attr_len > data.len() {
            break;
        }

        let attr_data = &data[attr_offset + 4..attr_offset + attr_len];

        match attr_type {
            // `struct inet_diag_meminfo` — four counters:
            //
            //   .idiag_rmem = sk_rmem_alloc_get(sk),        /* offset  0 */
            //   .idiag_wmem = sk->sk_wmem_queued,           /* offset  4 */
            //   .idiag_fmem = sk_forward_alloc_get(sk),     /* offset  8 */
            //   .idiag_tmem = sk_wmem_alloc_get(sk),        /* offset 12 */
            //
            // Note idiag_*w*mem at offset 4 is wmem_QUEUED and idiag_*t*mem at
            // offset 12 is wmem_ALLOC — nlink had those two backwards, so
            // ss-style `skmem:` printed `t` and `w` transposed (#222).
            //
            // Merge rather than assign: with_all_extensions() requests both
            // MEMINFO and SKMEMINFO, and whichever arm ran last used to
            // clobber the other's fields (#197).
            INET_DIAG_MEMINFO if attr_data.len() >= 16 => {
                let m = sock.mem_info.get_or_insert_with(MemInfo::default);
                m.rmem_alloc = u32_at(attr_data, 0);
                m.wmem_queued = u32_at(attr_data, 4);
                m.fwd_alloc = u32_at(attr_data, 8);
                m.wmem_alloc = u32_at(attr_data, 12);
            }
            // INET_DIAG_INFO's payload is protocol-dependent: `struct tcp_info`
            // for TCP, `struct sctp_info` for SCTP, `struct mptcp_info` for
            // MPTCP. All three clear the length guards inside parse_tcp_info,
            // so decoding unconditionally produced plausible-looking garbage
            // RTT / cwnd / bytes_acked from an SCTP socket (#225). Decode only
            // what we can name; the others are left as None rather than
            // reinterpreted.
            INET_DIAG_INFO if matches!(protocol, InetProtocol::Tcp) => {
                sock.tcp_info = Some(parse_tcp_info(attr_data));
            }
            INET_DIAG_CONG => {
                if let Ok(s) = std::str::from_utf8(attr_data) {
                    sock.congestion = Some(s.trim_end_matches('\0').to_string());
                }
            }
            INET_DIAG_TOS if !attr_data.is_empty() => {
                sock.tos = Some(attr_data[0]);
            }
            INET_DIAG_TCLASS if !attr_data.is_empty() => {
                sock.tclass = Some(attr_data[0]);
            }
            // `enum sk_meminfo_stats` — a superset of inet_diag_meminfo that
            // also carries the buffer sizes. This is the only attribute that
            // can fill rcvbuf/sndbuf/optmem/backlog/drops, and before #197
            // there was no builder that requested it.
            INET_DIAG_SKMEMINFO if attr_data.len() >= 36 => {
                sock.mem_info = Some(parse_sk_meminfo(attr_data));
            }
            INET_DIAG_SHUTDOWN if !attr_data.is_empty() => {
                sock.shutdown = Some(attr_data[0]);
            }
            INET_DIAG_MARK if attr_data.len() >= 4 => {
                sock.mark = Some(u32::from_ne_bytes([
                    attr_data[0],
                    attr_data[1],
                    attr_data[2],
                    attr_data[3],
                ]));
            }
            INET_DIAG_CGROUP_ID if attr_data.len() >= 8 => {
                sock.cgroup_id = Some(u64::from_ne_bytes([
                    attr_data[0],
                    attr_data[1],
                    attr_data[2],
                    attr_data[3],
                    attr_data[4],
                    attr_data[5],
                    attr_data[6],
                    attr_data[7],
                ]));
            }
            INET_DIAG_SKV6ONLY if !attr_data.is_empty() => {
                sock.v6only = Some(attr_data[0] != 0);
            }
            // CC-specific info structs (#163) — which one the kernel
            // emits depends on the socket's CC algorithm; all three
            // are gated by the VEGASINFO request bit. Rule-1
            // accept-larger: read the known prefix.
            INET_DIAG_VEGASINFO if attr_data.len() >= 16 => {
                let u = |o: usize| {
                    u32::from_ne_bytes([
                        attr_data[o],
                        attr_data[o + 1],
                        attr_data[o + 2],
                        attr_data[o + 3],
                    ])
                };
                sock.cc_info = Some(CcInfo::Vegas(VegasInfo {
                    enabled: u(0) != 0,
                    rttcnt: u(4),
                    rtt: u(8),
                    minrtt: u(12),
                }));
            }
            INET_DIAG_DCTCPINFO if attr_data.len() >= 16 => {
                let u = |o: usize| {
                    u32::from_ne_bytes([
                        attr_data[o],
                        attr_data[o + 1],
                        attr_data[o + 2],
                        attr_data[o + 3],
                    ])
                };
                sock.cc_info = Some(CcInfo::Dctcp(DctcpInfo {
                    enabled: u16::from_ne_bytes([attr_data[0], attr_data[1]]) != 0,
                    ce_state: u16::from_ne_bytes([attr_data[2], attr_data[3]]),
                    alpha: u(4),
                    ab_ecn: u(8),
                    ab_tot: u(12),
                }));
            }
            INET_DIAG_BBRINFO if attr_data.len() >= 20 => {
                let u = |o: usize| {
                    u32::from_ne_bytes([
                        attr_data[o],
                        attr_data[o + 1],
                        attr_data[o + 2],
                        attr_data[o + 3],
                    ])
                };
                sock.cc_info = Some(CcInfo::Bbr(BbrInfo {
                    bw: (u(0) as u64) | ((u(4) as u64) << 32),
                    min_rtt_us: u(8),
                    pacing_gain: u(12),
                    cwnd_gain: u(16),
                }));
            }
            _ => {}
        }

        // Align to 4 bytes
        attr_offset += (attr_len + 3) & !3;
    }

    Some(sock)
}

fn parse_tcp_info(data: &[u8]) -> TcpInfo {
    let mut info = TcpInfo::default();

    if data.len() < 104 {
        return info;
    }

    info.state = data[0];
    info.ca_state = data[1];
    info.retransmits = data[2];
    info.probes = data[3];
    info.backoff = data[4];
    info.options = data[5];
    info.wscale = data[6];
    info.delivery_rate_app_limited = data[7] != 0;

    info.rto = u32::from_ne_bytes([data[8], data[9], data[10], data[11]]);
    // ATO at 12-15 (skip)
    info.snd_mss = u32::from_ne_bytes([data[16], data[17], data[18], data[19]]);
    info.rcv_mss = u32::from_ne_bytes([data[20], data[21], data[22], data[23]]);

    info.unacked = u32::from_ne_bytes([data[24], data[25], data[26], data[27]]);
    info.sacked = u32::from_ne_bytes([data[28], data[29], data[30], data[31]]);
    info.lost = u32::from_ne_bytes([data[32], data[33], data[34], data[35]]);
    info.retrans = u32::from_ne_bytes([data[36], data[37], data[38], data[39]]);
    info.fackets = u32::from_ne_bytes([data[40], data[41], data[42], data[43]]);

    info.last_data_sent = u32::from_ne_bytes([data[44], data[45], data[46], data[47]]);
    info.last_ack_sent = u32::from_ne_bytes([data[48], data[49], data[50], data[51]]);
    info.last_data_recv = u32::from_ne_bytes([data[52], data[53], data[54], data[55]]);
    info.last_ack_recv = u32::from_ne_bytes([data[56], data[57], data[58], data[59]]);

    info.pmtu = u32::from_ne_bytes([data[60], data[61], data[62], data[63]]);
    info.rcv_ssthresh = u32::from_ne_bytes([data[64], data[65], data[66], data[67]]);
    info.rtt = u32::from_ne_bytes([data[68], data[69], data[70], data[71]]);
    info.rttvar = u32::from_ne_bytes([data[72], data[73], data[74], data[75]]);
    info.snd_ssthresh = u32::from_ne_bytes([data[76], data[77], data[78], data[79]]);
    info.snd_cwnd = u32::from_ne_bytes([data[80], data[81], data[82], data[83]]);
    info.advmss = u32::from_ne_bytes([data[84], data[85], data[86], data[87]]);
    info.reordering = u32::from_ne_bytes([data[88], data[89], data[90], data[91]]);

    info.rcv_rtt = u32::from_ne_bytes([data[92], data[93], data[94], data[95]]);
    info.rcv_space = u32::from_ne_bytes([data[96], data[97], data[98], data[99]]);

    info.total_retrans = u32::from_ne_bytes([data[100], data[101], data[102], data[103]]);

    // Extended fields if available
    if data.len() >= 160 {
        info.pacing_rate = u64::from_ne_bytes([
            data[104], data[105], data[106], data[107], data[108], data[109], data[110], data[111],
        ]);
        info.max_pacing_rate = u64::from_ne_bytes([
            data[112], data[113], data[114], data[115], data[116], data[117], data[118], data[119],
        ]);
        info.bytes_acked = u64::from_ne_bytes([
            data[120], data[121], data[122], data[123], data[124], data[125], data[126], data[127],
        ]);
        info.bytes_received = u64::from_ne_bytes([
            data[128], data[129], data[130], data[131], data[132], data[133], data[134], data[135],
        ]);
        info.segs_out = u32::from_ne_bytes([data[136], data[137], data[138], data[139]]);
        info.segs_in = u32::from_ne_bytes([data[140], data[141], data[142], data[143]]);
        info.notsent_bytes = u32::from_ne_bytes([data[144], data[145], data[146], data[147]]);
        info.min_rtt = u32::from_ne_bytes([data[148], data[149], data[150], data[151]]);
        info.data_segs_in = u32::from_ne_bytes([data[152], data[153], data[154], data[155]]);
        info.data_segs_out = u32::from_ne_bytes([data[156], data[157], data[158], data[159]]);
    }

    if data.len() >= 168 {
        info.delivery_rate = u64::from_ne_bytes([
            data[160], data[161], data[162], data[163], data[164], data[165], data[166], data[167],
        ]);
    }

    // Kernel 4.10+ block (busy_time .. sndbuf_limited) and 4.19+
    // block (delivered .. rcv_ooopack) — offsets verified against
    // uapi linux/tcp.h via offsetof (#171: bytes_sent/bytes_retrans
    // were declared on TcpInfo but never populated, so the byte-rate
    // tracker's retransmission ratio always read 0). Per parser
    // rule 1, each block is guarded with `>=` so both older kernels
    // (shorter struct) and newer ones (longer) parse cleanly.
    if data.len() >= 192 {
        info.busy_time = u64::from_ne_bytes([
            data[168], data[169], data[170], data[171], data[172], data[173], data[174], data[175],
        ]);
        info.rwnd_limited = u64::from_ne_bytes([
            data[176], data[177], data[178], data[179], data[180], data[181], data[182], data[183],
        ]);
        info.sndbuf_limited = u64::from_ne_bytes([
            data[184], data[185], data[186], data[187], data[188], data[189], data[190], data[191],
        ]);
    }

    if data.len() >= 232 {
        info.delivered = u32::from_ne_bytes([data[192], data[193], data[194], data[195]]);
        info.delivered_ce = u32::from_ne_bytes([data[196], data[197], data[198], data[199]]);
        info.bytes_sent = u64::from_ne_bytes([
            data[200], data[201], data[202], data[203], data[204], data[205], data[206], data[207],
        ]);
        info.bytes_retrans = u64::from_ne_bytes([
            data[208], data[209], data[210], data[211], data[212], data[213], data[214], data[215],
        ]);
        info.dsack_dups = u32::from_ne_bytes([data[216], data[217], data[218], data[219]]);
        info.reord_seen = u32::from_ne_bytes([data[220], data[221], data[222], data[223]]);
        info.rcv_ooopack = u32::from_ne_bytes([data[224], data[225], data[226], data[227]]);
        info.snd_wnd = u32::from_ne_bytes([data[228], data[229], data[230], data[231]]);
    }

    // What later kernels append (offsets from `offsetof` against the uapi
    // header; 6.18's AccECN block against its `include/uapi/linux/tcp.h`),
    // each read only when the kernel sent it (#166).
    let u16_at = |at: usize| u16::from_ne_bytes([data[at], data[at + 1]]);
    let u32_at = |at: usize| u32::from_ne_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
    if data.len() >= 240 {
        info.rcv_wnd = u32_at(232);
        info.rehash = u32_at(236);
    }
    if data.len() >= 248 {
        info.total_rto = u16_at(240);
        info.total_rto_recoveries = u16_at(242);
        info.total_rto_time = u32_at(244);
    }
    if data.len() >= 280 {
        info.received_ce = u32_at(248);
        info.delivered_e1_bytes = u32_at(252);
        info.delivered_e0_bytes = u32_at(256);
        info.delivered_ce_bytes = u32_at(260);
        info.received_e1_bytes = u32_at(264);
        info.received_e0_bytes = u32_at(268);
        info.received_ce_bytes = u32_at(272);
        info.accecn_fail_mode = u16_at(276);
        info.accecn_opt_seen = u16_at(278);
    }

    info
}

fn parse_unix_msg(data: &[u8]) -> Option<UnixSocket> {
    // Skip netlink header (16 bytes)
    if data.len() < 16 + 16 {
        return None;
    }

    let payload = &data[16..];

    // unix_diag_msg structure
    let family = payload[0];
    if family != libc::AF_UNIX as u8 {
        return None;
    }

    let socket_type = UnixType::from_u8(payload[1])?;
    let state_raw = payload[2];
    // pad at 3

    let inode = u32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let cookie = u64::from_ne_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ]);

    let state = match state_raw {
        1 => SocketState::Established,
        10 => SocketState::Listen,
        _ => SocketState::Close,
    };

    let mut sock = UnixSocket {
        socket_type,
        state,
        path: None,
        abstract_name: None,
        inode,
        cookie,
        peer_inode: None,
        vfs_dev: None,
        vfs_inode: None,
        recv_q: None,
        send_q: None,
        pending_connections: None,
        uid: None,
        mem_info: None,
        shutdown: None,
    };

    // Parse attributes
    let mut attr_offset = 16 + 16;
    while attr_offset + 4 <= data.len() {
        let attr_len = u16::from_ne_bytes([data[attr_offset], data[attr_offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[attr_offset + 2], data[attr_offset + 3]]);

        if attr_len < 4 || attr_offset + attr_len > data.len() {
            break;
        }

        let attr_data = &data[attr_offset + 4..attr_offset + attr_len];

        match attr_type {
            UNIX_DIAG_NAME if !attr_data.is_empty() => {
                if attr_data[0] == 0 {
                    // Abstract socket
                    if let Ok(s) = std::str::from_utf8(&attr_data[1..]) {
                        sock.abstract_name = Some(s.trim_end_matches('\0').to_string());
                    }
                } else if let Ok(s) = std::str::from_utf8(attr_data) {
                    sock.path = Some(s.trim_end_matches('\0').to_string());
                }
            }
            UNIX_DIAG_VFS if attr_data.len() >= 8 => {
                sock.vfs_inode = Some(u32::from_ne_bytes([
                    attr_data[0],
                    attr_data[1],
                    attr_data[2],
                    attr_data[3],
                ]));
                sock.vfs_dev = Some(u32::from_ne_bytes([
                    attr_data[4],
                    attr_data[5],
                    attr_data[6],
                    attr_data[7],
                ]));
            }
            UNIX_DIAG_PEER if attr_data.len() >= 4 => {
                sock.peer_inode = Some(u32::from_ne_bytes([
                    attr_data[0],
                    attr_data[1],
                    attr_data[2],
                    attr_data[3],
                ]));
            }
            UNIX_DIAG_ICONS => {
                let mut icons = Vec::new();
                let mut i = 0;
                while i + 4 <= attr_data.len() {
                    icons.push(u32::from_ne_bytes([
                        attr_data[i],
                        attr_data[i + 1],
                        attr_data[i + 2],
                        attr_data[i + 3],
                    ]));
                    i += 4;
                }
                if !icons.is_empty() {
                    sock.pending_connections = Some(icons);
                }
            }
            UNIX_DIAG_RQLEN if attr_data.len() >= 8 => {
                sock.recv_q = Some(u32::from_ne_bytes([
                    attr_data[0],
                    attr_data[1],
                    attr_data[2],
                    attr_data[3],
                ]));
                sock.send_q = Some(u32::from_ne_bytes([
                    attr_data[4],
                    attr_data[5],
                    attr_data[6],
                    attr_data[7],
                ]));
            }
            UNIX_DIAG_MEMINFO if attr_data.len() >= 36 => {
                sock.mem_info = Some(parse_sk_meminfo(attr_data));
            }
            UNIX_DIAG_SHUTDOWN if !attr_data.is_empty() => {
                sock.shutdown = Some(attr_data[0]);
            }
            UNIX_DIAG_UID if attr_data.len() >= 4 => {
                sock.uid = Some(u32::from_ne_bytes([
                    attr_data[0],
                    attr_data[1],
                    attr_data[2],
                    attr_data[3],
                ]));
            }
            _ => {}
        }

        attr_offset += (attr_len + 3) & !3;
    }

    Some(sock)
}

fn parse_netlink_msg(
    data: &[u8],
    filter: &NetlinkFilter,
) -> Option<crate::sockdiag::socket::NetlinkSocket> {
    // netlink_diag_msg: family(1) + type(1) + protocol(2) + state(4) +
    //                   portid(4) + dst_portid(4) + dst_group(4) + ino(4) + cookie(8) = 32 bytes
    if data.len() < 16 + 32 {
        return None;
    }

    let payload = &data[16..];

    let family = payload[0];
    if family != libc::AF_NETLINK as u8 {
        return None;
    }

    // payload[1] is ndiag_type (SOCK_RAW / SOCK_DGRAM)
    let protocol = u16::from_ne_bytes([payload[2], payload[3]]) as u8;

    // Apply protocol filter
    if let Some(filter_proto) = filter.protocol
        && protocol != filter_proto
    {
        return None;
    }

    // state at offset 4..8 (unused for display)
    let portid = u32::from_ne_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let dst_portid = u32::from_ne_bytes([payload[12], payload[13], payload[14], payload[15]]);
    let dst_group = u32::from_ne_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let inode = u32::from_ne_bytes([payload[20], payload[21], payload[22], payload[23]]);
    let cookie = u64::from_ne_bytes([
        payload[24],
        payload[25],
        payload[26],
        payload[27],
        payload[28],
        payload[29],
        payload[30],
        payload[31],
    ]);

    let mut sock = crate::sockdiag::socket::NetlinkSocket {
        protocol,
        portid,
        dst_portid,
        dst_group,
        groups: 0,
        inode,
        cookie,
        recv_q: None,
        send_q: None,
        mem_info: None,
    };

    // Parse attributes
    let mut attr_offset = 16 + 32;
    while attr_offset + 4 <= data.len() {
        let attr_len = u16::from_ne_bytes([data[attr_offset], data[attr_offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[attr_offset + 2], data[attr_offset + 3]]);

        if attr_len < 4 || attr_offset + attr_len > data.len() {
            break;
        }

        let attr_data = &data[attr_offset + 4..attr_offset + attr_len];

        match attr_type {
            NETLINK_DIAG_MEMINFO
                if attr_data.len() >= 36 => {
                    sock.mem_info = Some(parse_sk_meminfo(attr_data));
                }
            NETLINK_DIAG_GROUPS
                // Groups bitmask - first 4 bytes give us the basic groups u32
                if attr_data.len() >= 4 => {
                    sock.groups = u32::from_ne_bytes([
                        attr_data[0],
                        attr_data[1],
                        attr_data[2],
                        attr_data[3],
                    ]);
                }
            _ => {}
        }

        attr_offset += (attr_len + 3) & !3;
    }

    Some(sock)
}

#[cfg(test)]
mod packet_tests {
    use super::*;

    /// `parse_packet_msg` reconstructs a `PacketSocket` from a synthetic
    /// `packet_diag_msg` + `PACKET_DIAG_INFO`/`UID`/`FANOUT` attrs.
    #[test]
    fn parse_packet_msg_basic() {
        let mut msg = Vec::new();
        // 16-byte nlmsghdr (contents irrelevant to the parser — it reads
        // the payload starting at offset 16).
        msg.extend_from_slice(&[0u8; 16]);

        // packet_diag_msg: family, type, num(u16), ino(u32), cookie[2].
        msg.push(libc::AF_PACKET as u8); // pdiag_family
        msg.push(3); // pdiag_type = SOCK_RAW
        msg.extend_from_slice(&0x0003u16.to_ne_bytes()); // pdiag_num = ETH_P_ALL
        msg.extend_from_slice(&4242u32.to_ne_bytes()); // pdiag_ino
        msg.extend_from_slice(&7u64.to_ne_bytes()); // pdiag_cookie[2]

        // PACKET_DIAG_INFO (type 0): struct packet_diag_info, first u32 =
        // pdi_index (bound interface). 24 bytes of payload.
        let mut info = Vec::new();
        info.extend_from_slice(&5u32.to_ne_bytes()); // pdi_index = 5
        info.extend_from_slice(&[0u8; 20]); // remaining fields
        push_attr(&mut msg, 0, &info);

        // PACKET_DIAG_UID (type 5).
        push_attr(&mut msg, 5, &1000u32.to_ne_bytes());
        // PACKET_DIAG_FANOUT (type 4).
        push_attr(&mut msg, 4, &0xABCDu32.to_ne_bytes());

        let sock = parse_packet_msg(&msg).expect("should parse");
        assert_eq!(sock.socket_type, 3);
        assert_eq!(sock.protocol, 0x0003);
        assert_eq!(sock.inode, 4242);
        assert_eq!(sock.cookie, 7);
        assert_eq!(sock.interface, 5);
        assert_eq!(sock.uid, 1000);
        assert_eq!(sock.fanout, Some(0xABCD));
    }

    #[test]
    fn parse_packet_msg_rejects_short_and_wrong_family() {
        assert!(parse_packet_msg(&[0u8; 20]).is_none()); // too short
        let mut msg = vec![0u8; 16 + 16];
        msg[16] = libc::AF_INET as u8; // wrong family
        assert!(parse_packet_msg(&msg).is_none());
    }

    /// Append a netlink attribute (4-byte header + padded payload).
    fn push_attr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
        let len = (4 + payload.len()) as u16;
        buf.extend_from_slice(&len.to_ne_bytes());
        buf.extend_from_slice(&attr_type.to_ne_bytes());
        buf.extend_from_slice(payload);
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
    }
}

#[cfg(test)]
mod tcp_info_tests {
    use super::*;

    /// Write `v` (LE/native) at `off` into the buffer.
    fn put_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_ne_bytes());
    }
    fn put_u64(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_ne_bytes());
    }

    /// #171 — a full-size (232+ byte) kernel `tcp_info` populates the
    /// 4.10+/4.19+ tail fields, offsets pinned to uapi linux/tcp.h
    /// (verified via offsetof).
    #[test]
    fn parse_tcp_info_reads_post_168_fields() {
        let mut buf = vec![0u8; 232];
        put_u32(&mut buf, 68, 15_000); // rtt
        put_u64(&mut buf, 120, 1_000); // bytes_acked
        put_u64(&mut buf, 128, 2_000); // bytes_received
        put_u64(&mut buf, 160, 12_500_000); // delivery_rate
        put_u64(&mut buf, 168, 777); // busy_time
        put_u64(&mut buf, 176, 11); // rwnd_limited
        put_u64(&mut buf, 184, 22); // sndbuf_limited
        put_u32(&mut buf, 192, 33); // delivered
        put_u32(&mut buf, 196, 44); // delivered_ce
        put_u64(&mut buf, 200, 3_000); // bytes_sent
        put_u64(&mut buf, 208, 55); // bytes_retrans
        put_u32(&mut buf, 216, 66); // dsack_dups
        put_u32(&mut buf, 220, 77); // reord_seen
        put_u32(&mut buf, 224, 88); // rcv_ooopack
        put_u32(&mut buf, 228, 99); // snd_wnd

        let info = parse_tcp_info(&buf);
        assert_eq!(info.rtt, 15_000);
        assert_eq!(info.bytes_acked, 1_000);
        assert_eq!(info.bytes_received, 2_000);
        assert_eq!(info.delivery_rate, 12_500_000);
        assert_eq!(info.busy_time, 777);
        assert_eq!(info.rwnd_limited, 11);
        assert_eq!(info.sndbuf_limited, 22);
        assert_eq!(info.delivered, 33);
        assert_eq!(info.delivered_ce, 44);
        assert_eq!(info.bytes_sent, 3_000);
        assert_eq!(info.bytes_retrans, 55);
        assert_eq!(info.dsack_dups, 66);
        assert_eq!(info.reord_seen, 77);
        assert_eq!(info.rcv_ooopack, 88);
        assert_eq!(info.snd_wnd, 99);
    }

    /// The fields kernels appended after `snd_wnd`, at the offsets
    /// `offsetof` gives against the uapi header (6.18's AccECN block against
    /// its `tcp.h`), each read only when the kernel sent it (#166).
    #[test]
    fn parse_tcp_info_reads_the_rto_and_accecn_fields() {
        let mut buf = vec![0u8; 280];
        put_u32(&mut buf, 232, 65_536); // rcv_wnd
        put_u32(&mut buf, 236, 2); // rehash
        buf[240..242].copy_from_slice(&3u16.to_ne_bytes()); // total_rto
        buf[242..244].copy_from_slice(&4u16.to_ne_bytes()); // total_rto_recoveries
        put_u32(&mut buf, 244, 500); // total_rto_time
        for (i, at) in (248..276).step_by(4).enumerate() {
            put_u32(&mut buf, at, 10 + i as u32); // received_ce .. received_ce_bytes
        }
        buf[276..278].copy_from_slice(&1u16.to_ne_bytes()); // accecn_fail_mode
        buf[278..280].copy_from_slice(&2u16.to_ne_bytes()); // accecn_opt_seen

        let info = parse_tcp_info(&buf);
        assert_eq!((info.rcv_wnd, info.rehash), (65_536, 2));
        assert_eq!((info.total_rto, info.total_rto_recoveries, info.total_rto_time), (3, 4, 500));
        assert_eq!(
            [
                info.received_ce,
                info.delivered_e1_bytes,
                info.delivered_e0_bytes,
                info.delivered_ce_bytes,
                info.received_e1_bytes,
                info.received_e0_bytes,
                info.received_ce_bytes,
            ],
            [10, 11, 12, 13, 14, 15, 16]
        );
        assert_eq!((info.accecn_fail_mode, info.accecn_opt_seen), (1, 2));

        // A 6.12 kernel stops at total_rto_time: no AccECN.
        let info = parse_tcp_info(&buf[..248]);
        assert_eq!(info.total_rto_time, 500);
        assert_eq!((info.received_ce, info.accecn_opt_seen), (0, 0));
    }

    /// Rule 1 (accept-larger + graceful-shorter): older-kernel sizes
    /// leave the newer fields zeroed; oversized buffers parse the
    /// known prefix and ignore the tail.
    #[test]
    fn parse_tcp_info_handles_all_kernel_sizes() {
        for len in [104usize, 160, 168, 192, 232, 280, 512] {
            let buf = vec![0u8; len];
            let info = parse_tcp_info(&buf);
            assert_eq!(info.bytes_sent, 0);
            assert_eq!(info.snd_wnd, 0);
        }
        // Sub-minimum returns default without panicking.
        let info = parse_tcp_info(&[0u8; 40]);
        assert_eq!(info.rtt, 0);

        // A 231-byte buffer (one short of the 4.19 block) must not
        // read the partial block.
        let mut buf = vec![0u8; 231];
        buf[200..208].copy_from_slice(&12345u64.to_ne_bytes());
        let info = parse_tcp_info(&buf);
        assert_eq!(info.bytes_sent, 0, "partial 4.19 block must be ignored");
    }
}

#[cfg(test)]
mod cc_info_tests {
    use super::*;

    /// Build a minimal inet_diag response frame: 16-byte nlmsghdr +
    /// 72-byte inet_diag_msg (AF_INET, ESTABLISHED) + the given attrs.
    fn inet_frame(attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut msg = vec![0u8; 16 + 72];
        msg[16] = 2; // AF_INET
        msg[17] = 1; // TCP_ESTABLISHED
        for (attr_type, payload) in attrs {
            let attr_len = (4 + payload.len()) as u16;
            msg.extend_from_slice(&attr_len.to_ne_bytes());
            msg.extend_from_slice(&attr_type.to_ne_bytes());
            msg.extend_from_slice(payload);
            while !msg.len().is_multiple_of(4) {
                msg.push(0);
            }
        }
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());
        msg
    }

    fn u32s(vals: &[u32]) -> Vec<u8> {
        vals.iter().flat_map(|v| v.to_ne_bytes()).collect()
    }

    #[test]
    fn bbr_info_parses_with_bw_assembly() {
        // bw_lo, bw_hi, min_rtt, pacing_gain, cwnd_gain
        let frame = inet_frame(&[(INET_DIAG_BBRINFO, u32s(&[0x1000_0000, 0x2, 500, 320, 512]))]);
        let sock = parse_inet_msg(&frame, InetProtocol::Tcp).expect("parses");
        match sock.cc_info {
            Some(CcInfo::Bbr(bbr)) => {
                assert_eq!(bbr.bw, 0x1000_0000u64 | (0x2u64 << 32));
                assert_eq!(bbr.min_rtt_us, 500);
                assert_eq!(bbr.pacing_gain, 320);
                assert_eq!(bbr.cwnd_gain, 512);
            }
            other => panic!("expected Bbr, got {other:?}"),
        }
    }

    #[test]
    fn dctcp_info_parses_u16_head() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u16.to_ne_bytes()); // enabled
        payload.extend_from_slice(&2u16.to_ne_bytes()); // ce_state
        payload.extend_from_slice(&u32s(&[300, 400, 500])); // alpha, ab_ecn, ab_tot
        let frame = inet_frame(&[(INET_DIAG_DCTCPINFO, payload)]);
        let sock = parse_inet_msg(&frame, InetProtocol::Tcp).expect("parses");
        match sock.cc_info {
            Some(CcInfo::Dctcp(d)) => {
                assert!(d.enabled);
                assert_eq!(d.ce_state, 2);
                assert_eq!(d.alpha, 300);
                assert_eq!(d.ab_ecn, 400);
                assert_eq!(d.ab_tot, 500);
            }
            other => panic!("expected Dctcp, got {other:?}"),
        }
    }

    #[test]
    fn vegas_info_parses_and_short_attr_is_skipped() {
        let frame = inet_frame(&[(INET_DIAG_VEGASINFO, u32s(&[1, 7, 1500, 900]))]);
        let sock = parse_inet_msg(&frame, InetProtocol::Tcp).expect("parses");
        match sock.cc_info {
            Some(CcInfo::Vegas(v)) => {
                assert!(v.enabled);
                assert_eq!(v.rttcnt, 7);
                assert_eq!(v.rtt, 1500);
                assert_eq!(v.minrtt, 900);
            }
            other => panic!("expected Vegas, got {other:?}"),
        }

        // Truncated struct → attribute skipped, socket still parses.
        let frame = inet_frame(&[(INET_DIAG_BBRINFO, u32s(&[1, 2, 3]))]);
        let sock = parse_inet_msg(&frame, InetProtocol::Tcp).expect("parses");
        assert!(sock.cc_info.is_none());
    }

    /// #163 — pin the request-bit mapping. The kernel checks
    /// `ext & (1 << (attr - 1))`; before 0.24 `mask()` returned
    /// `1 << attr` (off by one, so with_mem_info() requested INFO).
    #[test]
    fn inet_extension_masks_match_kernel_bits() {
        use crate::sockdiag::InetExtension;
        assert_eq!(InetExtension::MemInfo.mask(), 1 << 0);
        assert_eq!(InetExtension::Info.mask(), 1 << 1);
        assert_eq!(InetExtension::VegasInfo.mask(), 1 << 2);
        assert_eq!(InetExtension::Cong.mask(), 1 << 3);
        assert_eq!(InetExtension::Tos.mask(), 1 << 4);
        assert_eq!(InetExtension::TClass.mask(), 1 << 5);
        assert_eq!(InetExtension::SkMemInfo.mask(), 1 << 6);
        assert_eq!(InetExtension::Shutdown.mask(), 1 << 7);
    }

    // ================================================================
    // MEMINFO / SKMEMINFO decode (#222, #197)
    // ================================================================

    /// **#222.** `struct inet_diag_meminfo` is
    /// `{ idiag_rmem, idiag_wmem, idiag_fmem, idiag_tmem }`, and the kernel
    /// fills it as:
    ///
    /// ```c
    /// .idiag_rmem = sk_rmem_alloc_get(sk),      /* offset  0 */
    /// .idiag_wmem = sk->sk_wmem_queued,         /* offset  4 */
    /// .idiag_fmem = sk_forward_alloc_get(sk),   /* offset  8 */
    /// .idiag_tmem = sk_wmem_alloc_get(sk),      /* offset 12 */
    /// ```
    ///
    /// So offset 4 is wmem_**queued** and offset 12 is wmem_**alloc** — the
    /// two nlink had backwards, which transposed `t` and `w` in ss-style
    /// `skmem:` output and made `total_mem()` sum the wrong pair.
    #[test]
    fn meminfo_offset_4_is_wmem_queued_and_offset_12_is_wmem_alloc() {
        let frame = inet_frame(&[(
            INET_DIAG_MEMINFO,
            u32s(&[11, 22, 33, 44]), // rmem, wmem_queued, fwd, wmem_alloc
        )]);
        let sock = parse_inet_msg(&frame, InetProtocol::Tcp).unwrap();
        let mem = sock.mem_info.unwrap();

        assert_eq!(mem.rmem_alloc, 11);
        assert_eq!(mem.wmem_queued, 22, "offset 4 is idiag_wmem = wmem_QUEUED");
        assert_eq!(mem.fwd_alloc, 33);
        assert_eq!(mem.wmem_alloc, 44, "offset 12 is idiag_tmem = wmem_ALLOC");

        // The four-field attribute cannot carry buffer sizes.
        assert_eq!(mem.rcvbuf, None);
        assert_eq!(mem.sndbuf, None);
        assert_eq!(mem.total_mem(), 11 + 44);
    }

    /// **#197.** `SKMEMINFO` is the only attribute that carries the buffer
    /// sizes, and no builder used to request it — so `rcvbuf`/`sndbuf` were
    /// structurally unfillable and read as a flat zero forever.
    #[test]
    fn skmeminfo_fills_the_buffer_sizes() {
        // enum sk_meminfo_stats: rmem_alloc, rcvbuf, wmem_alloc, sndbuf,
        //                        fwd_alloc, wmem_queued, optmem, backlog, drops
        let frame = inet_frame(&[(
            INET_DIAG_SKMEMINFO,
            u32s(&[1, 131_072, 3, 16_384, 5, 6, 7, 8, 9]),
        )]);
        let mem = parse_inet_msg(&frame, InetProtocol::Tcp)
            .unwrap()
            .mem_info
            .unwrap();

        assert_eq!(mem.rmem_alloc, 1);
        assert_eq!(mem.rcvbuf, Some(131_072));
        assert_eq!(mem.wmem_alloc, 3);
        assert_eq!(mem.sndbuf, Some(16_384));
        assert_eq!(mem.fwd_alloc, 5);
        assert_eq!(mem.wmem_queued, 6);
        assert_eq!(mem.optmem, Some(7));
        assert_eq!(mem.backlog, Some(8));
        assert_eq!(mem.drops, Some(9));
    }

    /// **#197.** Requesting both extensions must merge, not clobber.
    ///
    /// Both arms used to assign `sock.mem_info` outright, so with
    /// `with_all_extensions()` — which requests both — whichever attribute the
    /// kernel happened to emit last won, and the other's fields were lost.
    #[test]
    fn meminfo_and_skmeminfo_merge_in_either_order() {
        let meminfo = (INET_DIAG_MEMINFO, u32s(&[11, 22, 33, 44]));
        let skmeminfo = (
            INET_DIAG_SKMEMINFO,
            u32s(&[11, 131_072, 44, 16_384, 33, 22, 7, 8, 9]),
        );

        for attrs in [
            vec![meminfo.clone(), skmeminfo.clone()],
            vec![skmeminfo, meminfo],
        ] {
            let mem = parse_inet_msg(&inet_frame(&attrs), InetProtocol::Tcp)
                .unwrap()
                .mem_info
                .unwrap();
            assert_eq!(mem.wmem_alloc, 44);
            assert_eq!(mem.wmem_queued, 22);
            assert_eq!(
                mem.rcvbuf,
                Some(131_072),
                "the MEMINFO arm clobbered SKMEMINFO's buffer sizes"
            );
            assert_eq!(mem.sndbuf, Some(16_384));
        }
    }

    /// **#225.** `INET_DIAG_INFO` is `struct tcp_info` only for TCP.
    ///
    /// For SCTP it is `struct sctp_info` and for MPTCP `struct mptcp_info` —
    /// both long enough to clear parse_tcp_info's length guards, so decoding
    /// unconditionally produced plausible-looking garbage RTT and cwnd from a
    /// completely different struct.
    #[test]
    fn inet_diag_info_is_only_decoded_as_tcp_info_for_tcp() {
        let frame = inet_frame(&[(INET_DIAG_INFO, vec![0xAB; 232])]);

        assert!(
            parse_inet_msg(&frame, InetProtocol::Tcp)
                .unwrap()
                .tcp_info
                .is_some(),
            "TCP must still decode tcp_info"
        );
        assert!(
            parse_inet_msg(&frame, InetProtocol::Sctp)
                .unwrap()
                .tcp_info
                .is_none(),
            "an sctp_info payload was reinterpreted as tcp_info (#225)"
        );
    }

    /// **#225.** IPPROTO_MPTCP is 262 and does not fit `sdiag_protocol`.
    #[test]
    fn mptcp_does_not_fit_the_protocol_byte() {
        use crate::sockdiag::types::Protocol;

        assert_eq!(Protocol::Mptcp.number_u32(), 262);
        assert!(
            !Protocol::Mptcp.fits_in_u8(),
            "MPTCP must be flagged as needing INET_DIAG_REQ_PROTOCOL — \
             without it the kernel sees the truncated byte 6 (plain TCP) \
             and returns every TCP socket, each stamped Mptcp"
        );
        assert_eq!(Protocol::Mptcp.number(), 6, "262 & 0xff");

        for p in [Protocol::Tcp, Protocol::Udp, Protocol::Sctp, Protocol::Dccp] {
            assert!(p.fits_in_u8());
            assert_eq!(p.number() as u32, p.number_u32());
        }
    }
}
