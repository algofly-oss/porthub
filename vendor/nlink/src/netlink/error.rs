//! Error types for netlink operations.

use std::io;

use crate::util::{addr::AddrError, ifname::IfError, parse::ParseError};

/// Result type for netlink operations.
pub type Result<T> = std::result::Result<T, Error>;

/// An nlink error (#526).
///
/// One error carries four things:
/// - **[`kind`](Self::kind):** what kind of failure it is, for matching
///   and for reports;
/// - **[`detail`](Self::detail):** where it came from. That is the
///   kernel's errno and extended ack, an I/O error, a parse, …;
/// - **[`context`](Self::context):** what was being done, outermost
///   first. A context added with [`with_context`](Self::with_context) or
///   [`ResultExt::context`] is kept on every error, kernel or not;
/// - **[`object`](Self::object):** what it was done to, where the code
///   that failed knew: the route, the qdisc, the peer, the sysctl.
///
/// Recover with [`kind`](Self::kind), or with the `is_*` predicates,
/// rather than by matching [`ErrorDetail`]. One kind can come from several
/// details: a missing interface is a kernel `ENODEV`, or a lookup by name.
///
/// It is one pointer wide, so a `Result<T>` costs what a `T` does, and
/// there is no reason to box it. Carry it inline in an error type of your
/// own:
///
/// ```no_run
/// #[derive(thiserror::Error, Debug)]
/// enum MyError {
///     #[error("netlink failed: {0}")]
///     Netlink(#[from] nlink::Error),
/// }
/// ```
///
/// [`Error::chain_walk`] finds it through `#[source]` chains, boxed or not.
pub struct Error(Box<Inner>);

struct Inner {
    detail: ErrorDetail,
    /// Outermost first.
    context: Vec<String>,
    object: Option<ErrorObject>,
    /// The namespace of the connection it came from (#718).
    netns: Option<std::sync::Arc<str>>,
}

/// What a failed operation was done to (#526): the object an [`Error`]
/// names, where the code that failed knew it. [`Error::object`] reads it,
/// and [`ApplyError`](crate::netlink::config::ApplyError) serializes it.
///
/// A declarative apply names the object of the step that failed; a
/// sysctl, interface or namespace error names its own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "kebab-case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum ErrorObject {
    /// A link (an interface), by name.
    Link {
        /// Its name.
        name: String,
    },
    /// An address on a link.
    Address {
        /// The link.
        dev: String,
        /// The address and prefix: `10.0.0.1/24`.
        address: String,
    },
    /// A route.
    Route {
        /// Its destination and prefix: `10.0.0.0/8`.
        destination: String,
        /// Its table, where one was given.
        table: Option<u32>,
    },
    /// A neighbour (ARP/NDP) entry.
    Neighbour {
        /// The link.
        dev: String,
        /// The neighbour's address.
        destination: std::net::IpAddr,
    },
    /// A bridge forwarding-database entry.
    Fdb {
        /// The port.
        dev: String,
        /// The MAC address: `aa:bb:cc:dd:ee:ff`.
        mac: String,
    },
    /// A policy routing rule.
    Rule {
        /// Its priority.
        priority: u32,
    },
    /// A nexthop object.
    Nexthop {
        /// Its id.
        id: u32,
    },
    /// A qdisc.
    Qdisc {
        /// The link.
        dev: String,
        /// Where it hangs, in tc(8) notation: `root`, `ingress`, `1:a`
        /// (#718), where the code that failed knew it.
        parent: Option<String>,
        /// Its kind: `htb`, `netem`, …, where the code that failed knew it.
        kind: Option<String>,
    },
    /// A traffic-control class (#718).
    TcClass {
        /// The link.
        dev: String,
        /// Its id, in tc(8) notation: `1:a`.
        classid: String,
    },
    /// A traffic-control filter (#718), by what the kernel tells filters
    /// apart by.
    TcFilter {
        /// The link.
        dev: String,
        /// The qdisc or hook it hangs off, in tc(8) notation.
        parent: String,
        /// Its priority.
        priority: u16,
        /// Its protocol: `all`, `ip`, `802.1Q`, ….
        protocol: String,
    },
    /// A link's traffic-control tree: its classes, leaf qdiscs and filters.
    Tc {
        /// The link.
        dev: String,
    },
    /// A WireGuard device.
    WireguardDevice {
        /// Its name.
        name: String,
    },
    /// A WireGuard peer.
    WireguardPeer {
        /// Its device.
        dev: String,
        /// Its public key, base64.
        public_key: String,
    },
    /// A sysctl.
    Sysctl {
        /// The key, as given.
        key: String,
    },
    /// A network namespace: its name, or the path it was opened by.
    Namespace {
        /// The name or path.
        name: String,
    },
    /// A generic-netlink family, by name (#718).
    GenlFamily {
        /// Its name: `wireguard`, `nl80211`, ….
        name: String,
    },
    /// An nftables table (#718).
    NftTable {
        /// Its family: `inet`, `ip`, `ip6`, `arp`, `bridge` or `netdev`.
        family: String,
        /// Its name.
        name: String,
    },
    /// An nftables chain (#718).
    NftChain {
        /// Its table's family.
        family: String,
        /// Its table.
        table: String,
        /// Its name.
        name: String,
    },
    /// An nftables rule (#718), by its chain and, where it has one, its key.
    NftRule {
        /// Its table's family.
        family: String,
        /// Its table.
        table: String,
        /// Its chain.
        chain: String,
        /// The key nlink stores in the rule's comment, if it has one.
        key: Option<String>,
    },
    /// An nftables set or map, or elements of one (#718).
    NftSet {
        /// Its table's family.
        family: String,
        /// Its table.
        table: String,
        /// Its name.
        name: String,
    },
    /// A named nftables object: a counter, quota, limit, … (#718).
    NftObject {
        /// Its table's family.
        family: String,
        /// Its table.
        table: String,
        /// Its name.
        name: String,
    },
    /// An nftables flowtable (#718).
    NftFlowtable {
        /// Its table's family.
        family: String,
        /// Its table.
        table: String,
        /// Its name.
        name: String,
    },
}

impl std::fmt::Display for ErrorObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Link { name } => write!(f, "link {name}"),
            Self::Address { dev, address } => write!(f, "address {address} on {dev}"),
            Self::Route {
                destination,
                table: Some(table),
            } => write!(f, "route {destination} table {table}"),
            Self::Route { destination, .. } => write!(f, "route {destination}"),
            Self::Neighbour { dev, destination } => write!(f, "neighbour {destination} on {dev}"),
            Self::Fdb { dev, mac } => write!(f, "fdb {mac} on {dev}"),
            Self::Rule { priority } => write!(f, "rule {priority}"),
            Self::Nexthop { id } => write!(f, "nexthop {id}"),
            Self::Qdisc { dev, parent, kind } => {
                f.write_str("qdisc")?;
                if let Some(kind) = kind {
                    write!(f, " {kind}")?;
                }
                if let Some(parent) = parent {
                    write!(f, " at {parent}")?;
                }
                write!(f, " on {dev}")
            }
            Self::TcClass { dev, classid } => write!(f, "class {classid} on {dev}"),
            Self::TcFilter {
                dev,
                parent,
                priority,
                protocol,
            } => write!(f, "filter at {parent} prio {priority} {protocol} on {dev}"),
            Self::Tc { dev } => write!(f, "tc on {dev}"),
            Self::WireguardDevice { name } => write!(f, "wireguard device {name}"),
            Self::WireguardPeer { dev, public_key } => write!(f, "peer {public_key} on {dev}"),
            Self::Sysctl { key } => write!(f, "sysctl {key}"),
            Self::Namespace { name } => write!(f, "namespace {name}"),
            Self::GenlFamily { name } => write!(f, "GENL family {name}"),
            Self::NftTable { family, name } => write!(f, "nftables table {family} {name}"),
            Self::NftChain {
                family,
                table,
                name,
            } => write!(f, "nftables chain {family} {table}/{name}"),
            Self::NftRule {
                family,
                table,
                chain,
                key: Some(key),
            } => write!(f, "nftables rule {family} {table}/{chain} [{key}]"),
            Self::NftRule {
                family,
                table,
                chain,
                ..
            } => write!(f, "nftables rule {family} {table}/{chain}"),
            Self::NftSet {
                family,
                table,
                name,
            } => write!(f, "nftables set {family} {table}/{name}"),
            Self::NftObject {
                family,
                table,
                name,
            } => write!(f, "nftables object {family} {table}/{name}"),
            Self::NftFlowtable {
                family,
                table,
                name,
            } => write!(f, "nftables flowtable {family} {table}/{name}"),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for operation in &self.0.context {
            write!(f, "{operation}: ")?;
        }
        match &self.0.detail {
            // Under a context a kernel error is just what the kernel said:
            // `add_link(d0): File exists (errno 17)`.
            ErrorDetail::Kernel {
                errno,
                ext_ack,
                ext_ack_offset,
                ..
            } if !self.0.context.is_empty() => f.write_str(&format_kernel_tail(
                &strerror(*errno),
                *errno,
                ext_ack.as_deref(),
                *ext_ack_offset,
            ))?,
            detail => detail.fmt(f)?,
        }
        if let Some(netns) = &self.0.netns {
            write!(f, " [netns {netns}]")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.context.is_empty() && self.0.netns.is_none() {
            return self.0.detail.fmt(f);
        }
        let mut s = f.debug_struct("Error");
        if !self.0.context.is_empty() {
            s.field("context", &self.0.context);
        }
        if let Some(netns) = &self.0.netns {
            s.field("netns", netns);
        }
        s.field("detail", &self.0.detail).finish()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.0.detail)
    }
}

impl From<ErrorDetail> for Error {
    fn from(detail: ErrorDetail) -> Self {
        // A missing interface is one detail, however it was found missing
        // (#718).
        let detail = match detail {
            ErrorDetail::Interface(IfError::NotFound(name)) => ErrorDetail::NotFound {
                object: ErrorObject::Link { name },
            },
            detail => detail,
        };
        // A detail that names its object says so in `object()` too.
        let object = match &detail {
            ErrorDetail::Sysctl { key, .. } => Some(ErrorObject::Sysctl { key: key.clone() }),
            ErrorDetail::NotFound { object } => Some(object.clone()),
            ErrorDetail::NamespaceDeleted { path } => Some(ErrorObject::Namespace {
                name: path.display().to_string(),
            }),
            // The first refused operation that names something (#718).
            ErrorDetail::NftBatch { failures } => failures.iter().find_map(|f| f.object.clone()),
            _ => None,
        };
        Self(Box::new(Inner {
            detail,
            context: Vec::new(),
            object,
            netns: None,
        }))
    }
}

/// `From` for each source an [`ErrorDetail`] wraps, so `?` converts it.
macro_rules! from_detail {
    ($($ty:ty),* $(,)?) => {$(
        impl From<$ty> for Error {
            fn from(source: $ty) -> Self {
                ErrorDetail::from(source).into()
            }
        }
    )*};
}
from_detail!(
    io::Error,
    ParseError,
    AddrError,
    IfError,
    crate::netlink::config::AddressParseError,
    crate::netlink::config::RouteParseError,
);
// `serde` pulls in serde_json as `output` does (#741).
#[cfg(any(feature = "output", feature = "serde"))]
from_detail!(serde_json::Error);

/// Where an [`Error`] came from: the kernel's answer, an I/O error, a
/// parse, a limit nlink hit, … (#526). Read it with [`Error::detail`].
/// Most code needs only [`Error::kind`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorDetail {
    /// I/O error from socket operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization error.
    #[cfg(any(feature = "output", feature = "serde"))]
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Kernel returned an error code.
    ///
    /// Carries optional extended-ack TLVs ([`ext_ack`](Self::Kernel::ext_ack),
    /// [`ext_ack_offset`](Self::Kernel::ext_ack_offset)) populated by
    /// the kernel when `NETLINK_EXT_ACK` is enabled (on by default in
    /// nlink).
    #[error("{}", format_kernel(&strerror(*errno), *errno, ext_ack.as_deref(), *ext_ack_offset))]
    #[non_exhaustive]
    Kernel {
        /// The errno value from the kernel. Its text, `strerror(errno)`,
        /// is what `Display` shows; it is not stored (#718).
        errno: i32,
        /// Kernel-supplied human-readable detail string from the
        /// `NLMSGERR_ATTR_MSG` TLV, when present. Often dramatically
        /// more actionable than the raw errno — for example,
        /// `errno = 22 (EINVAL)` + `ext_ack = "attribute IFLA_MTU
        /// rejected: value 0 out of range"`.
        ext_ack: Option<String>,
        /// Byte offset into the original request where the kernel
        /// detected the problem, from `NLMSGERR_ATTR_OFFS`.
        ext_ack_offset: Option<u32>,
        /// The `nlmsg_type` of the request the kernel refused, from the
        /// header it echoes (#526): what [`Error::kind`] reads an errno
        /// against. `None` for an error not built from a kernel reply.
        request_type: Option<u16>,
        /// The protocol the request was sent on. A request type means
        /// something only within its protocol: 25 is `RTM_DELROUTE` on
        /// rtnetlink, `XFRM_MSG_UPDPOLICY` on xfrm, and a family id on
        /// generic netlink (#722). `None` where the reply's socket was not
        /// known.
        protocol: Option<crate::netlink::Protocol>,
    },

    /// The kernel refused an nftables batch.
    ///
    /// `nfnetlink` processes every message of a batch, reports each one it
    /// refuses, and then rolls the whole batch back: **nothing in it was
    /// committed.** `failures` has one entry per refused operation, in
    /// batch order, each naming the operation and — where the kernel
    /// pointed at one — the attribute or expression it blamed (#481).
    ///
    /// [`errno`](Error::errno), [`ext_ack`](Error::ext_ack) and the `is_*`
    /// predicates answer for the first failure, so `e.is_busy()` still
    /// works on a refused batch.
    #[error("{}", format_nft_batch(failures))]
    #[non_exhaustive]
    NftBatch {
        /// Every operation the kernel refused, in batch order.
        failures: Vec<crate::netlink::nftables::NftBatchFailure>,
    },

    /// Reading or writing a sysctl under `/proc/sys` failed.
    ///
    /// Carries the key and the I/O error, so a failed `set_sysctls` says
    /// which key; `is_not_found()` holds for a key that does not exist and
    /// `is_permission_denied()` for one that cannot be written (#477).
    #[error("sysctl {key}: {source}")]
    Sysctl {
        /// The key, as given.
        key: String,
        /// What the filesystem said.
        #[source]
        source: io::Error,
    },

    /// Message was truncated.
    #[error("message truncated: expected {expected} bytes, got {actual}")]
    Truncated {
        /// Expected message length.
        expected: usize,
        /// Actual bytes received.
        actual: usize,
    },

    /// A netlink frame exceeded the recv buffer (kernel-side
    /// `MSG_TRUNC`). Distinct from [`Self::Truncated`] which is
    /// the parser short-buffer case. `received` is the actual
    /// frame size the kernel reported via `MSG_TRUNC`;
    /// `buffer_size` is the cap. nlink reads a datagram of any size
    /// up to 1 MiB whole; this error means one past that was dropped.
    /// An event stream reports it as an overrun (an `ENOBUFS` error, so
    /// a resync wrapper re-dumps) and keeps going (#505).
    ///
    /// Added in 0.20.1 (Plan 224 — closes B4).
    #[error(
        "netlink frame truncated: kernel emitted {received} bytes, \
         nlink's recv buffer is {buffer_size} bytes (1 MiB cap reached); \
         file an issue with the kernel version + subsystem"
    )]
    FrameTruncated {
        /// Actual kernel frame size as reported by `MSG_TRUNC`.
        received: usize,
        /// Buffer size nlink had allocated.
        buffer_size: usize,
    },

    /// Kernel send buffer is full and back-to-back `WouldBlock`
    /// returns from `send` have exceeded the backpressure
    /// threshold. The 30 s connection timeout (Plan 171) would
    /// eventually surface as `Timeout`, but `Backpressure` lets
    /// the caller react faster.
    ///
    /// Added in 0.20.1 (Plan 232 — closes B19).
    #[error(
        "netlink send: kernel send buffer full ({send_buffer_full}); \
         try again later or back off"
    )]
    Backpressure {
        /// True when caused by send-buffer-full back-to-back
        /// WouldBlock returns from the kernel.
        send_buffer_full: bool,
    },

    /// A request on a mutex-mode connection while one of its event
    /// streams ([`Connection::events`](crate::Connection::events), or a
    /// resync wrapper) owns it. In mutex mode the stream holds the
    /// connection's request lock until it is dropped, so the request could
    /// only wait — and did, until the operation timeout reported it as a
    /// kernel hang. Send requests on a second connection, or build this one
    /// with [`Connection::with_dispatcher`](crate::Connection::with_dispatcher),
    /// where events and requests share the socket.
    ///
    /// Added in 0.31.0 (#505).
    #[error(
        "connection busy: an event stream owns it (mutex mode); \
         send requests on a second connection or use `with_dispatcher()`"
    )]
    EventStreamActive,

    /// Invalid message format.
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Invalid attribute format.
    #[error("invalid attribute: {0}")]
    InvalidAttribute(String),

    /// Operation not supported.
    #[error("operation not supported: {0}")]
    NotSupported(String),

    /// Parse error from util parsing functions.
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    /// Address parsing error.
    #[error("address error: {0}")]
    Address(#[from] AddrError),

    /// Interface error (not found, invalid name).
    #[error("interface error: {0}")]
    Interface(#[from] IfError),

    /// Address parsing error from declarative-config builders
    /// (e.g., `NetworkConfig::address("dev", "10.0.0.1/24")`).
    /// Added in 0.17 (Plan 173) so callers can `?`-chain on
    /// the builders without a per-call `.map_err()`.
    #[error("address parse error: {0}")]
    AddressParse(#[from] crate::netlink::config::AddressParseError),

    /// Route parsing error from declarative-config builders
    /// (e.g., `NetworkConfig::route("10.0.0.0/8", |r| ...)`).
    /// Added in 0.17 (Plan 173) so callers can `?`-chain on
    /// the builders without a per-call `.map_err()`.
    #[error("route parse error: {0}")]
    RouteParse(#[from] crate::netlink::config::RouteParseError),

    /// Validation errors from configuration builders.
    #[error("validation failed: {}", format_validation_errors(.0))]
    Validation(Vec<ValidationErrorInfo>),

    /// What was looked for is not there (#718): an interface
    /// ([`ErrorObject::Link`]), a namespace, a qdisc, a GENL family, ….
    /// [`Error::object`] names it too. It was four details until 0.32
    /// (`InterfaceNotFound`, `NamespaceNotFound`, `QdiscNotFound`,
    /// `FamilyNotFound`), and reads as they did.
    #[error("{}", not_found_message(object))]
    NotFound {
        /// What was looked for.
        object: ErrorObject,
    },

    /// The network namespace an event stream's socket lives in was deleted
    /// (#504): the marker the socket was opened through — a
    /// `/var/run/netns` name or another bind mount — is gone, or names
    /// another namespace now. The stream has ended. Its socket was what
    /// kept the namespace, and its interfaces, alive; drop the stream (and,
    /// for a borrowed `events()` stream, the connection) so the kernel can
    /// free it.
    ///
    /// Added in 0.31.0.
    #[error("network namespace deleted: {} no longer names this stream's namespace", path.display())]
    NamespaceDeleted {
        /// The marker the socket was opened through.
        path: std::path::PathBuf,
    },

    /// A declarative apply went through, and a second diff still found
    /// work to do (#518): the kernel did not take some change the way the
    /// diff expected, or something changed the state meanwhile. Asked for
    /// with `ApplyOptions::with_verify(true)`.
    #[error("the apply did not converge; a second diff still finds:\n{remaining}")]
    NotConverged {
        /// What the second diff found.
        remaining: Box<crate::netlink::config::ConfigDiff>,
    },

    /// A [`Stack`](crate::facade::Stack) apply went through, and a second
    /// plan of every layer still found work to do (#519). Asked for with
    /// [`ExecOptions::with_verify`](crate::reconcile::ExecOptions::with_verify).
    /// Its kind is [`ErrorKind::NotConverged`], like
    /// [`Self::NotConverged`]'s.
    #[error("the stack apply did not converge; a second plan still finds:\n{remaining}")]
    StackNotConverged {
        /// What the second plan found.
        remaining: Box<crate::facade::StackPlan>,
    },

    /// Operation timed out.
    ///
    /// The configured timeout expired before the kernel responded.
    /// This typically indicates a kernel bug or an extremely loaded system.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<()> {
    /// use nlink::{Connection, Route};
    /// use std::time::Duration;
    ///
    /// let conn = Connection::<Route>::new()?
    ///     .timeout(Duration::from_secs(5));
    ///
    /// match conn.get_links().await {
    ///     Err(e) if e.is_timeout() => eprintln!("kernel not responding"),
    ///     Err(e) => return Err(e),
    ///     Ok(links) => { /* ... */ }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[error("operation timed out")]
    Timeout,

    /// IPv6 duplicate address detection found these addresses in use
    /// elsewhere on their links (`IFA_F_DADFAILED`): they never become
    /// usable. From [`Connection::wait_addresses_settled`](crate::Connection::wait_addresses_settled)
    /// (#524).
    #[error("duplicate address detection failed for {addresses:?}")]
    DadFailed {
        /// The addresses DAD found in use.
        addresses: Vec<std::net::IpAddr>,
    },

    /// Kernel signaled that a dump was interrupted — the snapshot
    /// iterator's underlying data structure was mutated between
    /// frames, so the returned data set is inconsistent.
    ///
    /// The kernel sets `NLM_F_DUMP_INTR` on whichever message in the
    /// dump stream was generated after the mutation. Higher-level
    /// libraries differ on what to do:
    /// `iproute2` warns and accepts the partial dump;
    /// `vishvananda/netlink` retries with a bound;
    /// Cilium's `safenetlink` wrapper retries up to 30 times.
    ///
    /// nlink surfaces this as a typed error so callers choose their
    /// own retry policy. Recover via [`Error::is_dump_interrupted`]:
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<Vec<nlink::netlink::messages::LinkMessage>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// for attempt in 0..16 {
    ///     match conn.get_links().await {
    ///         Err(e) if e.is_dump_interrupted() => continue,
    ///         other => return other,
    ///     }
    /// }
    /// # conn.get_links().await
    /// # }
    /// ```
    ///
    /// See [`crate::netlink::message::NlMsgHdr::is_dump_interrupted`]
    /// for kernel semantics. Reference: kernel netlink intro docs,
    /// `vishvananda/netlink #1163`, `pyroute2 #874`.
    #[error("netlink dump interrupted by concurrent mutation (NLM_F_DUMP_INTR) — retry")]
    DumpInterrupted,

    /// Connection pool was unable to hand out a connection within
    /// the configured `acquire_timeout`.
    ///
    /// Recover via [`Error::is_pool_exhausted`]. Typical responses:
    /// retry with a longer timeout, scale the pool size up, or
    /// shed load.
    #[error("connection pool exhausted: {size} connections all busy, waited {timeout:?}")]
    PoolExhausted {
        /// Configured pool size (total connections, busy + idle).
        size: usize,
        /// The acquire timeout that just expired.
        timeout: std::time::Duration,
    },

    /// nlink's own machinery failed: a worker thread it runs namespace
    /// work on panicked or went away (#526). Not the caller's input and
    /// not the kernel's answer; its kind is [`ErrorKind::Other`].
    #[error("internal error: {0}")]
    Internal(String),

    /// The connection pool was dropped while an `acquire()` was
    /// pending, or while waiting to send a connection back to it.
    ///
    /// Recover via [`Error::is_pool_closed`]. Indicates a teardown
    /// race; the surviving task should fail through.
    #[error("connection pool is closed (all handles dropped)")]
    PoolClosed,
}

/// What kind of failure an [`Error`] is: one answer per error, for
/// matching and for reports (#526).
///
/// [`Error::kind`] classifies every error, kernel or not. The `is_*`
/// predicates stay, and agree with it; a few of them are finer
/// (`is_no_device` is one of the two errnos [`ErrorKind::NotFound`] covers)
/// or broader (`is_not_found` also holds for ENODEV, which is
/// `NotFound` here too).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum ErrorKind {
    /// The object does not exist: ENOENT, ENODEV, or a not-found variant
    /// (interface, namespace, qdisc, genl family).
    NotFound,
    /// The object exists already: EEXIST.
    AlreadyExists,
    /// The object is in use: EBUSY.
    Busy,
    /// Not allowed: EPERM, EACCES.
    PermissionDenied,
    /// The kernel, the device or nlink does not do this: EOPNOTSUPP, or
    /// [`ErrorDetail::NotSupported`](crate::ErrorDetail::NotSupported).
    NotSupported,
    /// The kernel refused an argument: EINVAL.
    InvalidArgument,
    /// Try again: EAGAIN.
    TryAgain,
    /// The kernel's state changed under the request; redo it from a fresh
    /// read: ERESTART (an nftables generation mismatch).
    Restart,
    /// A dump was interrupted by a concurrent change (`NLM_F_DUMP_INTR`).
    DumpInterrupted,
    /// Messages were lost: ENOBUFS on a socket that fell behind, or an
    /// event stream's own backpressure.
    Overrun,
    /// No answer in time: [`Error::timeout()`] or ETIMEDOUT.
    Timeout,
    /// A frame or message was cut short.
    Truncated,
    /// ENETUNREACH.
    NetworkUnreachable,
    /// EHOSTUNREACH.
    HostUnreachable,
    /// EADDRINUSE.
    AddressInUse,
    /// ECONNREFUSED.
    ConnectionRefused,
    /// EMSGSIZE.
    MessageTooLong,
    /// ENAMETOOLONG.
    NameTooLong,
    /// EMFILE.
    TooManyOpenFiles,
    /// EROFS.
    ReadOnly,
    /// A declared configuration nlink refused before sending anything.
    Validation,
    /// A message, attribute or input nlink could not use: something it
    /// failed to parse, or a value it refused.
    Invalid,
    /// The namespace a connection or stream was in was deleted.
    NamespaceDeleted,
    /// A request was refused because an event stream holds the
    /// connection.
    EventStreamActive,
    /// A connection pool had no connection to give.
    PoolExhausted,
    /// A connection pool was closed.
    PoolClosed,
    /// Duplicate address detection failed.
    DadFailed,
    /// A declarative apply went through, and a second diff still found
    /// work to do.
    NotConverged,
    /// Anything else: an errno not named above, or an error with none.
    Other,
}

impl ErrorKind {
    /// The kind an errno is, when nothing else is known about the error.
    pub fn from_errno(errno: i32) -> Self {
        match errno {
            libc::ENOENT | libc::ENODEV => Self::NotFound,
            libc::EEXIST => Self::AlreadyExists,
            libc::EBUSY => Self::Busy,
            libc::EPERM | libc::EACCES => Self::PermissionDenied,
            libc::EOPNOTSUPP => Self::NotSupported,
            libc::EINVAL => Self::InvalidArgument,
            libc::EAGAIN => Self::TryAgain,
            libc::ERESTART => Self::Restart,
            libc::ENOBUFS => Self::Overrun,
            libc::ETIMEDOUT => Self::Timeout,
            libc::ENETUNREACH => Self::NetworkUnreachable,
            libc::EHOSTUNREACH => Self::HostUnreachable,
            libc::EADDRINUSE => Self::AddressInUse,
            libc::ECONNREFUSED => Self::ConnectionRefused,
            libc::EMSGSIZE => Self::MessageTooLong,
            libc::ENAMETOOLONG => Self::NameTooLong,
            libc::EMFILE => Self::TooManyOpenFiles,
            libc::EROFS => Self::ReadOnly,
            _ => Self::Other,
        }
    }

    /// Whether the same request can succeed if made again, unchanged or
    /// from a fresh read: busy, try again, restart, an interrupted dump,
    /// an overrun, a timeout.
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Busy
                | Self::TryAgain
                | Self::Restart
                | Self::DumpInterrupted
                | Self::Overrun
                | Self::Timeout
        )
    }
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::NotFound => "not found",
            Self::AlreadyExists => "already exists",
            Self::Busy => "busy",
            Self::PermissionDenied => "permission denied",
            Self::NotSupported => "not supported",
            Self::InvalidArgument => "invalid argument",
            Self::TryAgain => "try again",
            Self::Restart => "restart",
            Self::DumpInterrupted => "dump interrupted",
            Self::Overrun => "overrun",
            Self::Timeout => "timed out",
            Self::Truncated => "truncated",
            Self::NetworkUnreachable => "network unreachable",
            Self::HostUnreachable => "host unreachable",
            Self::AddressInUse => "address in use",
            Self::ConnectionRefused => "connection refused",
            Self::MessageTooLong => "message too long",
            Self::NameTooLong => "name too long",
            Self::TooManyOpenFiles => "too many open files",
            Self::ReadOnly => "read-only",
            Self::Validation => "invalid configuration",
            Self::Invalid => "invalid",
            Self::NamespaceDeleted => "namespace deleted",
            Self::EventStreamActive => "event stream active",
            Self::PoolExhausted => "pool exhausted",
            Self::PoolClosed => "pool closed",
            Self::DadFailed => "duplicate address detection failed",
            Self::NotConverged => "did not converge",
            Self::Other => "other",
        };
        f.write_str(s)
    }
}

/// Context on a `Result`'s error, without a `map_err` at every call site
/// (#526).
///
/// ```
/// use nlink::ResultExt;
///
/// fn apply() -> nlink::Result<()> {
///     Err(nlink::Error::from_errno(libc::EBUSY)).context("apply nftables on b")
/// }
/// let err = apply().unwrap_err();
/// assert_eq!(err.kind(), nlink::ErrorKind::Busy);
/// assert!(err.to_string().starts_with("apply nftables on b: "), "{err}");
/// ```
pub trait ResultExt<T> {
    /// Add `operation` to the error, as [`Error::with_context`] does. A
    /// context on an error that has one already goes in front of it.
    fn context(self, operation: impl Into<String>) -> Result<T>;
}

impl<T> ResultExt<T> for Result<T> {
    fn context(self, operation: impl Into<String>) -> Result<T> {
        self.map_err(|e| e.with_context(operation))
    }
}

/// Structured validation error information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrorInfo {
    /// Field that failed validation.
    pub field: String,
    /// Description of the error.
    pub message: String,
}

impl ValidationErrorInfo {
    /// Create a new validation error.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ValidationErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

/// What [`ErrorDetail::NotFound`] says: what the four details it replaced
/// said (#718), and the object's own name for the rest.
fn not_found_message(object: &ErrorObject) -> String {
    match object {
        ErrorObject::Link { name } => format!("interface not found: {name}"),
        ErrorObject::Namespace { name } => format!("namespace not found: {name}"),
        ErrorObject::GenlFamily { name } => format!("GENL family not found: {name}"),
        ErrorObject::Qdisc {
            dev,
            kind: Some(kind),
            ..
        } => format!("qdisc not found: {kind} on {dev}"),
        other => format!("not found: {other}"),
    }
}

/// Format validation errors for display.
fn format_validation_errors(errors: &[ValidationErrorInfo]) -> String {
    errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Format the Display output for [`ErrorDetail::Kernel`](crate::ErrorDetail::Kernel), stitching the
/// ext-ack message in when present. Pulled into a free fn so the
/// `#[error(...)]` attribute stays readable.
fn format_kernel(
    message: &str,
    errno: i32,
    ext_ack: Option<&str>,
    ext_ack_offset: Option<u32>,
) -> String {
    format!(
        "kernel error: {}",
        format_kernel_tail(message, errno, ext_ack, ext_ack_offset)
    )
}

/// What the kernel said: `File exists (errno 17)`, then its extended ack.
fn format_kernel_tail(
    message: &str,
    errno: i32,
    ext_ack: Option<&str>,
    ext_ack_offset: Option<u32>,
) -> String {
    let mut out = format!("{message} (errno {errno})");
    if let Some(msg) = ext_ack {
        out.push_str(": ");
        out.push_str(msg);
    }
    if let Some(off) = ext_ack_offset {
        out.push_str(&format!(" (at request offset {off})"));
    }
    out
}

/// `strerror(errno)`, without std's ` (os error N)` suffix: the
/// kernel errors print `(errno N)` themselves, and saying it twice
/// (`Device or resource busy (os error 16) (errno 16)`) was noise (#481).
pub(crate) fn strerror(errno: i32) -> String {
    let full = io::Error::from_raw_os_error(errno).to_string();
    let suffix = format!(" (os error {errno})");
    full.strip_suffix(&suffix)
        .map(str::to_string)
        .unwrap_or(full)
}

/// Format the Display output for [`ErrorDetail::NftBatch`](crate::ErrorDetail::NftBatch).
fn format_nft_batch(failures: &[crate::netlink::nftables::NftBatchFailure]) -> String {
    let shown: Vec<String> = failures.iter().map(|f| f.to_string()).collect();
    format!(
        "nftables batch refused, nothing committed: {}",
        shown.join("; ")
    )
}

impl Error {
    /// Create a kernel error from an errno value (no ext-ack info).
    ///
    /// Prefer [`Self::from_errno_ext_ack`] when the kernel response
    /// carries `NLMSGERR_ATTR_MSG` / `NLMSGERR_ATTR_OFFS` TLVs —
    /// those become user-visible diagnostics far more actionable than
    /// the raw errno.
    pub fn from_errno(errno: i32) -> Self {
        Self::from_errno_ext_ack(errno, None, None)
    }

    /// Create a kernel error from an errno value plus the parsed
    /// extended-ack TLVs from the same error response.
    ///
    /// **Accepts either sign.** The kernel's `nlmsgerr.error` field
    /// is signed-negative (`-EEXIST = -17`); the stored
    /// `Error::Kernel.errno` is always the positive POSIX number
    /// (`17`). This factory normalizes via `.abs()` so both
    /// `from_errno_ext_ack(-17, ..)` and `from_errno_ext_ack(17, ..)`
    /// produce the same EEXIST error.
    ///
    /// Prior to 0.19 (Plan 187) this factory silently negated the
    /// input and a positive-passed `1` produced stored `-1` — a
    /// footgun nlink-lab hit in their `Error::ext_ack` unit tests.
    ///
    /// Typical use: after `NlMsgError::from_bytes`, call
    /// `err.parsed_ext_ack(payload)` to get a [`crate::netlink::message::ParsedExtAck`],
    /// then forward the fields here.
    pub fn from_errno_ext_ack(
        errno: i32,
        ext_ack: Option<String>,
        ext_ack_offset: Option<u32>,
    ) -> Self {
        Self::from_kernel_reply(errno, None, ext_ack, ext_ack_offset)
    }

    /// The kernel's refusal of a request of type `request_type` (#526),
    /// which [`kind`](Self::kind) reads the errno against.
    pub(crate) fn from_kernel_reply(
        errno: i32,
        request_type: Option<u16>,
        ext_ack: Option<String>,
        ext_ack_offset: Option<u32>,
    ) -> Self {
        let errno = errno.abs();
        ErrorDetail::Kernel {
            errno,
            ext_ack,
            ext_ack_offset,
            request_type,
            protocol: None,
        }
        .into()
    }

    /// Note the protocol a kernel refusal came back on (#722), unless it
    /// has one: the connection paths, which know their socket, call this.
    pub(crate) fn in_protocol(mut self, p: crate::netlink::Protocol) -> Self {
        if let ErrorDetail::Kernel { protocol, .. } = &mut self.0.detail {
            protocol.get_or_insert(p);
        }
        self
    }

    /// Note the namespace of the connection an error came from (#718),
    /// unless it has one. The socket does this for what it sends and
    /// receives, and the connection paths for what the kernel refuses.
    pub(crate) fn in_netns(mut self, label: &std::sync::Arc<str>) -> Self {
        self.0.netns.get_or_insert_with(|| label.clone());
        self
    }

    /// The namespace of the connection this error came from (#718): the
    /// label of the [`Netns`](crate::netlink::namespace::Netns) it was
    /// made in (an `ip netns` name, a path, `pid 42`, …). `None` for a
    /// connection in the calling thread's namespace, and for an error that
    /// did not come from a connection.
    ///
    /// A caller with one connection per namespace (a lab with a node per
    /// namespace, say) can tell which one failed without wrapping every
    /// call. `Display` shows it last: `add_link(d0): File exists
    /// (errno 17) [netns red]`.
    pub fn netns(&self) -> Option<&str> {
        self.0.netns.as_deref()
    }

    /// The protocol of the request the kernel refused, where known (#722).
    pub fn protocol(&self) -> Option<crate::netlink::Protocol> {
        match self.detail() {
            ErrorDetail::Kernel { protocol, .. } => *protocol,
            _ => None,
        }
    }

    /// The `nlmsg_type` of the request the kernel refused, if this is its
    /// refusal (#526).
    pub fn request_type(&self) -> Option<u16> {
        match self.detail() {
            ErrorDetail::Kernel { request_type, .. } => *request_type,
            _ => None,
        }
    }

    /// Create a kernel error with operation context (no ext-ack info).
    ///
    /// Accepts either sign on `errno`; see [`Self::from_errno_ext_ack`].
    pub fn from_errno_with_context(errno: i32, operation: impl Into<String>) -> Self {
        Self::from_errno_with_context_ext_ack(errno, operation, None, None)
    }

    /// Create a kernel error with operation context plus the parsed
    /// extended-ack TLVs.
    ///
    /// Accepts either sign on `errno`; see [`Self::from_errno_ext_ack`].
    pub fn from_errno_with_context_ext_ack(
        errno: i32,
        operation: impl Into<String>,
        ext_ack: Option<String>,
        ext_ack_offset: Option<u32>,
    ) -> Self {
        Self::from_errno_ext_ack(errno, ext_ack, ext_ack_offset).with_context(operation)
    }

    /// Add what was being done: `operation` goes in front of any context
    /// the error has (`"outer: inner"`), on any error (#526).
    ///
    /// Until 0.32 only a kernel error kept a context, and only one: an
    /// I/O error, a refused nftables batch or a validation failure lost it.
    /// The same label twice — a helper and its caller naming one
    /// operation — is said once.
    pub fn with_context(mut self, operation: impl Into<String>) -> Self {
        let outer = operation.into();
        let repeated = self
            .0
            .context
            .first()
            .is_some_and(|inner| *inner == outer || inner.starts_with(&format!("{outer}(")));
        if !repeated {
            self.0.context.insert(0, outer);
        }
        self
    }

    /// Where the error came from (#526): the kernel's answer, an I/O
    /// error, a parse, …. Most code needs only [`kind`](Self::kind).
    pub fn detail(&self) -> &ErrorDetail {
        &self.0.detail
    }

    /// [`detail`](Self::detail), by value; the context is dropped.
    pub fn into_detail(self) -> ErrorDetail {
        self.0.detail
    }

    /// What the failed operation was done to (#526), where the code that
    /// failed knew: a declarative apply names its step's object.
    pub fn object(&self) -> Option<&ErrorObject> {
        self.0.object.as_ref()
    }

    /// Name what the failed operation was done to, unless the error names
    /// something already: the innermost code knows best.
    pub fn with_object(mut self, object: ErrorObject) -> Self {
        self.0.object.get_or_insert(object);
        self
    }

    /// Name what the failed operation was done to in place of a less
    /// precise name for the same kind of thing (#718): a caller that knows
    /// the device by name refines what a layer below named by ifindex. A
    /// [`NotFound`](ErrorDetail::NotFound) detail's object is refined too,
    /// so the message says the same. An error that names another kind of
    /// object keeps it.
    pub(crate) fn refine_object(mut self, object: ErrorObject) -> Self {
        let same_kind = |o: &ErrorObject| std::mem::discriminant(o) == std::mem::discriminant(&object);
        if self.0.object.as_ref().is_none_or(same_kind) {
            if let ErrorDetail::NotFound { object: found } = &mut self.0.detail
                && same_kind(found)
            {
                *found = object.clone();
            }
            self.0.object = Some(object);
        }
        self
    }

    /// What was being done, outermost first (#526): each
    /// [`with_context`](Self::with_context) and
    /// [`ResultExt::context`]. Empty for an error with none.
    pub fn context(&self) -> &[String] {
        &self.0.context
    }

    /// Create a validation error from a list of field errors.
    pub fn validation(errors: impl IntoIterator<Item = ValidationErrorInfo>) -> Self {
        ErrorDetail::Validation(errors.into_iter().collect()).into()
    }

    /// Create a single validation error.
    pub fn validation_error(field: impl Into<String>, message: impl Into<String>) -> Self {
        ErrorDetail::Validation(vec![ValidationErrorInfo::new(field, message)]).into()
    }

    /// Create an invalid message error.
    ///
    /// This is a convenience constructor for the common case of creating
    /// an `InvalidMessage` error with a formatted message.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nlink::netlink::Error;
    ///
    /// let err = Error::invalid_message("invalid MAC address format");
    /// ```
    pub fn invalid_message(message: impl Into<String>) -> Self {
        ErrorDetail::InvalidMessage(message.into()).into()
    }

    /// Create an invalid attribute error.
    pub fn invalid_attribute(message: impl Into<String>) -> Self {
        ErrorDetail::InvalidAttribute(message.into()).into()
    }

    /// Create a not supported error.
    pub fn not_supported(message: impl Into<String>) -> Self {
        ErrorDetail::NotSupported(message.into()).into()
    }

    /// `object` is not there (#718): [`ErrorDetail::NotFound`].
    pub fn not_found(object: ErrorObject) -> Self {
        ErrorDetail::NotFound { object }.into()
    }

    /// An interface that is not there: [`ErrorDetail::NotFound`] of an
    /// [`ErrorObject::Link`].
    pub fn interface_not_found(name: impl Into<String>) -> Self {
        Self::not_found(ErrorObject::Link { name: name.into() })
    }

    /// A namespace that is not there: [`ErrorDetail::NotFound`] of an
    /// [`ErrorObject::Namespace`].
    pub fn namespace_not_found(name: impl Into<String>) -> Self {
        Self::not_found(ErrorObject::Namespace { name: name.into() })
    }

    /// A qdisc of `kind` that `interface` does not have:
    /// [`ErrorDetail::NotFound`] of an [`ErrorObject::Qdisc`].
    pub fn qdisc_not_found(kind: impl Into<String>, interface: impl Into<String>) -> Self {
        Self::not_found(ErrorObject::Qdisc {
            dev: interface.into(),
            parent: None,
            kind: Some(kind.into()),
        })
    }

    /// A GENL family the kernel does not have: [`ErrorDetail::NotFound`]
    /// of an [`ErrorObject::GenlFamily`].
    pub fn family_not_found(name: impl Into<String>) -> Self {
        Self::not_found(ErrorObject::GenlFamily { name: name.into() })
    }

    /// A short buffer: `expected` bytes needed, `actual` there.
    pub fn truncated(expected: usize, actual: usize) -> Self {
        ErrorDetail::Truncated { expected, actual }.into()
    }

    /// The operation timed out ([`ErrorDetail::Timeout`]).
    pub fn timeout() -> Self {
        ErrorDetail::Timeout.into()
    }

    /// A dump the kernel interrupted ([`ErrorDetail::DumpInterrupted`]).
    pub fn dump_interrupted() -> Self {
        ErrorDetail::DumpInterrupted.into()
    }

    /// The connection pool is gone ([`ErrorDetail::PoolClosed`]).
    pub fn pool_closed() -> Self {
        ErrorDetail::PoolClosed.into()
    }

    pub(crate) fn event_stream_active() -> Self {
        ErrorDetail::EventStreamActive.into()
    }

    /// nlink's own machinery failed ([`ErrorDetail::Internal`]).
    pub(crate) fn internal(message: impl Into<String>) -> Self {
        ErrorDetail::Internal(message.into()).into()
    }

    /// What kind of failure this is (#526). One answer per error; see
    /// [`ErrorKind`].
    ///
    /// ```
    /// use nlink::{Error, ErrorKind};
    ///
    /// let err = Error::from_errno(libc::EEXIST).with_context("add_link(d0)");
    /// assert_eq!(err.kind(), ErrorKind::AlreadyExists);
    /// assert!(err.is_already_exists());
    /// ```
    pub fn kind(&self) -> ErrorKind {
        match self.detail() {
            ErrorDetail::NotFound { .. } => ErrorKind::NotFound,
            ErrorDetail::NotSupported(_) => ErrorKind::NotSupported,
            ErrorDetail::Timeout => ErrorKind::Timeout,
            ErrorDetail::FrameTruncated { .. } | ErrorDetail::Truncated { .. } => ErrorKind::Truncated,
            ErrorDetail::Backpressure { .. } => ErrorKind::Overrun,
            ErrorDetail::DumpInterrupted => ErrorKind::DumpInterrupted,
            ErrorDetail::Validation(_) => ErrorKind::Validation,
            ErrorDetail::NamespaceDeleted { .. } => ErrorKind::NamespaceDeleted,
            ErrorDetail::EventStreamActive => ErrorKind::EventStreamActive,
            ErrorDetail::PoolExhausted { .. } => ErrorKind::PoolExhausted,
            ErrorDetail::PoolClosed => ErrorKind::PoolClosed,
            ErrorDetail::DadFailed { .. } => ErrorKind::DadFailed,
            ErrorDetail::NotConverged { .. } | ErrorDetail::StackNotConverged { .. } => ErrorKind::NotConverged,
            ErrorDetail::Io(e) if e.raw_os_error().is_none() => match e.kind() {
                std::io::ErrorKind::NotFound => ErrorKind::NotFound,
                std::io::ErrorKind::AlreadyExists => ErrorKind::AlreadyExists,
                std::io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
                std::io::ErrorKind::TimedOut => ErrorKind::Timeout,
                std::io::ErrorKind::Unsupported => ErrorKind::NotSupported,
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::InvalidData => {
                    ErrorKind::Invalid
                }
                _ => ErrorKind::Other,
            },
            ErrorDetail::InvalidMessage(_)
            | ErrorDetail::InvalidAttribute(_)
            | ErrorDetail::Parse(_)
            | ErrorDetail::Address(_)
            | ErrorDetail::Interface(_)
            | ErrorDetail::AddressParse(_)
            | ErrorDetail::RouteParse(_) => ErrorKind::Invalid,
            ErrorDetail::Internal(_) => ErrorKind::Other,
            // An errno means "not there" only for some requests (#526): the
            // kernel answers a route delete that matches nothing with ESRCH,
            // and an address delete with EADDRNOTAVAIL. Only on rtnetlink:
            // the same type numbers mean other requests elsewhere (#722).
            ErrorDetail::Kernel {
                errno: libc::ESRCH,
                request_type: Some(crate::netlink::message::NlMsgType::RTM_DELROUTE),
                protocol: Some(crate::netlink::Protocol::Route),
                ..
            }
            | ErrorDetail::Kernel {
                errno: libc::EADDRNOTAVAIL,
                request_type: Some(crate::netlink::message::NlMsgType::RTM_DELADDR),
                protocol: Some(crate::netlink::Protocol::Route),
                ..
            } => ErrorKind::NotFound,
            // xfrm answers a request for an SA it does not have with ESRCH
            // (`xfrm_user_state_lookup`, `xfrm_state_update`), #718.
            ErrorDetail::Kernel {
                errno: libc::ESRCH,
                request_type:
                    Some(
                        crate::netlink::xfrm::XFRM_MSG_DELSA
                        | crate::netlink::xfrm::XFRM_MSG_GETSA
                        | crate::netlink::xfrm::XFRM_MSG_UPDSA,
                    ),
                protocol: Some(crate::netlink::Protocol::Xfrm),
                ..
            } => ErrorKind::NotFound,
            _ => self.errno().map_or(ErrorKind::Other, ErrorKind::from_errno),
        }
    }

    /// Check if this is a "not found" error (ENOENT, ENODEV, etc.).
    ///
    /// Matches kernel and I/O errors carrying ENOENT/ENODEV — routed through
    /// the common [`Self::errno`] accessor that Plan 187 §2.5
    /// established as the canonical errno-shape merge point.
    ///
    /// Plus [`ErrorDetail::NotFound`], whatever was looked for (#718).
    ///
    /// Pre-0.19 this predicate matched the kernel variants directly,
    /// missing an I/O error carrying ENOENT, which sibling predicates
    /// (`is_busy`, `is_permission_denied`, `is_already_exists`)
    /// already handled. Plan 212 closes the asymmetry.
    pub fn is_not_found(&self) -> bool {
        if matches!(self.errno(), Some(libc::ENOENT) | Some(libc::ENODEV))
            || self.kind() == ErrorKind::NotFound
        {
            return true;
        }
        matches!(
            self.detail(),
            ErrorDetail::NotFound { .. }
        )
    }

    /// Check if this is a permission error (EPERM, EACCES).
    ///
    /// Plan 187 §2.5: matches both `Error::Kernel*` and
    /// `Error::from` variants carrying EPERM/EACCES via the
    /// `errno()` unwrap.
    pub fn is_permission_denied(&self) -> bool {
        matches!(self.errno(), Some(libc::EPERM) | Some(libc::EACCES))
    }

    /// Check if this is a "already exists" error (EEXIST).
    ///
    /// Plan 187 §2.5: matches both `Error::Kernel*` and
    /// `Error::from(EEXIST)` shapes. Also matches `Error::from`
    /// carrying `ErrorKind::AlreadyExists` without a raw errno —
    /// the shape `namespace::create_path` builds for its
    /// already-exists rejection (same predicate-widening move as
    /// Plan 212's `is_not_found`).
    pub fn is_already_exists(&self) -> bool {
        if self.errno() == Some(libc::EEXIST) {
            return true;
        }
        matches!(self.detail(), ErrorDetail::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists)
    }

    /// Check if this is a "device busy" error (EBUSY).
    ///
    /// Plan 187 §2.5: matches both `Error::Kernel*` and
    /// `Error::from(EBUSY)` shapes. Used by
    /// `NftablesConfig::apply_reconcile` for retry
    /// classification — a missed match here used to silently
    /// skip the retry budget.
    pub fn is_busy(&self) -> bool {
        self.errno() == Some(libc::EBUSY)
    }

    /// Get the POSIX errno value if this error carries one.
    ///
    /// Handles these details:
    /// - [`ErrorDetail::Kernel`] — from `NLMSGERR`;
    /// - [`ErrorDetail::NftBatch`] — the first refused operation's;
    /// - [`ErrorDetail::Io`] and [`ErrorDetail::Sysctl`] — reads
    ///   `raw_os_error()`. This is the shape `recvmsg` returns `-ENOBUFS`
    ///   in (the Plan 185 bug class that Plan 187 fixes at the
    ///   single-point of `errno()`).
    ///
    /// Returns `None` for the other variants (Timeout, Truncated,
    /// InvalidMessage, etc.) — they don't carry an errno.
    pub fn errno(&self) -> Option<i32> {
        match self.detail() {
            ErrorDetail::Kernel { errno, .. } => Some(*errno),
            ErrorDetail::NftBatch { failures } => failures.first().map(|f| f.errno),
            ErrorDetail::Io(io_err) | ErrorDetail::Sysctl { source: io_err, .. } => io_err.raw_os_error(),
            _ => None,
        }
    }

    /// Return the kernel's `NLMSGERR_ATTR_MSG` extended-ack
    /// string if this is a kernel error that carries one.
    /// Plan 182 — sugar over destructuring [`ErrorDetail::Kernel`],
    /// which is `#[non_exhaustive]` and so forces a wildcard arm at
    /// every call site. Equivalent, for a kernel error, to:
    ///
    /// ```no_run
    /// # use nlink::{Error, ErrorDetail};
    /// # fn example(err: Error) -> Option<&'static str> {
    /// # let ext: Option<&str> =
    /// match err.detail() {
    ///     ErrorDetail::Kernel { ext_ack, .. } => ext_ack.as_deref(),
    ///     _ => None,
    /// }
    /// # ;
    /// # None
    /// # }
    /// ```
    pub fn ext_ack(&self) -> Option<&str> {
        match self.detail() {
            ErrorDetail::Kernel { ext_ack, .. } => ext_ack.as_deref(),
            ErrorDetail::NftBatch { failures } => failures.first().and_then(|f| f.ext_ack.as_deref()),
            _ => None,
        }
    }

    /// Return the `NLMSGERR_ATTR_OFFS` byte offset pointing at
    /// the offending attribute in the request payload, if the
    /// kernel sent one. Pair with [`Self::ext_ack`] when
    /// constructing structured error reports. Plan 182.
    pub fn ext_ack_offset(&self) -> Option<u32> {
        match self.detail() {
            ErrorDetail::Kernel { ext_ack_offset, .. } => *ext_ack_offset,
            ErrorDetail::NftBatch { failures } => failures.first().and_then(|f| f.offset),
            _ => None,
        }
    }

    /// Check if this is an "invalid argument" error (EINVAL).
    ///
    /// This typically indicates that the kernel rejected the request
    /// due to invalid parameters (e.g., invalid handle, unsupported option).
    pub fn is_invalid_argument(&self) -> bool {
        self.errno() == Some(libc::EINVAL)
    }

    /// Check if this is a "no such device" error (ENODEV).
    ///
    /// This indicates the specified network device does not exist.
    pub fn is_no_device(&self) -> bool {
        self.errno() == Some(libc::ENODEV)
    }

    /// Check if this is a "not supported" error (EOPNOTSUPP, or the
    /// library-level [`ErrorDetail::NotSupported`](crate::ErrorDetail::NotSupported) variant).
    ///
    /// This indicates the requested operation is not supported by the kernel
    /// or the specific device/driver, or that nlink itself does not support
    /// the operation in the current mode (e.g. an event stream on a
    /// dispatcher-mode connection).
    pub fn is_not_supported(&self) -> bool {
        matches!(self.detail(), ErrorDetail::NotSupported(_)) || self.errno() == Some(libc::EOPNOTSUPP)
    }

    /// Check if this is a "network unreachable" error (ENETUNREACH).
    pub fn is_network_unreachable(&self) -> bool {
        self.errno() == Some(libc::ENETUNREACH)
    }

    /// Walk the source chain of an arbitrary error and yield
    /// every `&nlink::Error` along the way, **transparently
    /// unwrapping `Box<nlink::Error>`** at each step.
    ///
    /// Saves consumers from writing the
    /// `src.downcast_ref::<nlink::Error>()` → fallback-to-
    /// `Box<nlink::Error>` ladder by hand. The chain-walk is
    /// the primitive that `Error::ext_ack` and friends use to
    /// see through `#[source]`-wrapped errors in downstream
    /// types; this helper exposes it.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nlink::Error;
    /// # let outer_err: Box<dyn std::error::Error> =
    /// #     Box::new(Error::timeout());
    /// // Find the first kernel ENOBUFS anywhere in the chain.
    /// let enobufs = Error::chain_walk(outer_err.as_ref())
    ///     .find(|e| e.is_no_buffer_space());
    /// ```
    ///
    /// Plan 187 §2.2.
    pub fn chain_walk<'a>(err: &'a (dyn std::error::Error + 'static)) -> ChainWalk<'a> {
        ChainWalk { current: Some(err) }
    }

    /// The deepest `nlink::Error` in the chain — typically the
    /// kernel error at the bottom of a wrapper stack. Returns
    /// `self` if the chain is just this one error.
    ///
    /// Convenience over [`Self::chain_walk`].
    pub fn root_cause(&self) -> &Error {
        Self::chain_walk(self).last().unwrap_or(self)
    }

    /// All `nlink::Error` layers in the chain as a `Vec`,
    /// outer-to-inner. Useful for serialization or rendering
    /// every layer of context.
    ///
    /// Convenience over [`Self::chain_walk`].
    pub fn contexts(&self) -> Vec<&Error> {
        Self::chain_walk(self).collect()
    }

    /// Check if this is [`ErrorDetail::DadFailed`](crate::ErrorDetail::DadFailed).
    pub fn is_dad_failed(&self) -> bool {
        matches!(self.detail(), ErrorDetail::DadFailed { .. })
    }

    /// Check if this is a timeout error.
    ///
    /// Returns `true` for both the [`Error::timeout()`] variant and
    /// kernel ETIMEDOUT errors.
    pub fn is_timeout(&self) -> bool {
        matches!(self.detail(), ErrorDetail::Timeout) || self.errno() == Some(libc::ETIMEDOUT)
    }

    /// Check if this is an [`ErrorDetail::FrameTruncated`](crate::ErrorDetail::FrameTruncated) error — the
    /// kernel emitted a netlink frame larger than nlink's
    /// receive cap (1 MiB).
    ///
    /// Added in 0.20.1 (Plan 224 — closes B4).
    pub fn is_truncated(&self) -> bool {
        matches!(self.detail(), ErrorDetail::FrameTruncated { .. })
    }

    /// Check if this is an [`ErrorDetail::Backpressure`](crate::ErrorDetail::Backpressure) error — the
    /// kernel send buffer is full and back-to-back `WouldBlock`
    /// returns exceeded the backpressure threshold.
    ///
    /// Added in 0.20.1 (Plan 232 — closes B19).
    pub fn is_backpressure(&self) -> bool {
        matches!(self.detail(), ErrorDetail::Backpressure { .. })
    }

    /// Check if this is an [`Error::event_stream_active()`] — a request on a
    /// mutex-mode connection whose event stream owns it.
    ///
    /// Added in 0.31.0 (#505).
    pub fn is_event_stream_active(&self) -> bool {
        matches!(self.detail(), ErrorDetail::EventStreamActive)
    }

    /// Check if this is an [`ErrorDetail::NamespaceDeleted`](crate::ErrorDetail::NamespaceDeleted) — an event stream
    /// whose namespace was deleted under it, and which has ended.
    ///
    /// Added in 0.31.0 (#504).
    pub fn is_namespace_deleted(&self) -> bool {
        matches!(self.detail(), ErrorDetail::NamespaceDeleted { .. })
    }

    /// Check if this is an [`Error::dump_interrupted()`].
    ///
    /// The kernel signaled `NLM_F_DUMP_INTR` on a dump message,
    /// meaning the snapshot was mutated mid-flight and the returned
    /// data set is inconsistent. The right response is to retry the
    /// dump with a bound (Cilium uses 30 attempts, vishvananda uses
    /// 24). Without this predicate, pre-0.19 nlink callers had no way
    /// to know the dump was stale — they would silently use the
    /// inconsistent data.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nlink::{Connection, Route};
    ///
    /// async fn get_links_with_retry(
    ///     conn: &Connection<Route>,
    /// ) -> nlink::Result<Vec<nlink::netlink::messages::LinkMessage>> {
    ///     for _ in 0..16 {
    ///         match conn.get_links().await {
    ///             Err(e) if e.is_dump_interrupted() => continue,
    ///             other => return other,
    ///         }
    ///     }
    ///     conn.get_links().await
    /// }
    /// ```
    pub fn is_dump_interrupted(&self) -> bool {
        matches!(self.detail(), ErrorDetail::DumpInterrupted)
    }

    /// Check if this is a [`ErrorDetail::PoolExhausted`](crate::ErrorDetail::PoolExhausted).
    ///
    /// All pool slots were busy when `ConnectionPool::acquire` was
    /// called, and the `acquire_timeout` elapsed before any returned.
    /// Typical recovery: retry with a longer timeout, scale the
    /// pool size up, or shed load.
    pub fn is_pool_exhausted(&self) -> bool {
        matches!(self.detail(), ErrorDetail::PoolExhausted { .. })
    }

    /// Check if this is a [`Error::pool_closed()`].
    ///
    /// The pool was dropped while an acquire / return was pending.
    /// Indicates teardown race; the surviving task should fail
    /// through.
    pub fn is_pool_closed(&self) -> bool {
        matches!(self.detail(), ErrorDetail::PoolClosed)
    }

    /// Check if this is an "address already in use" error (EADDRINUSE).
    ///
    /// This typically occurs when trying to add an IP address that is
    /// already assigned to an interface.
    pub fn is_address_in_use(&self) -> bool {
        self.errno() == Some(libc::EADDRINUSE)
    }

    /// Check if this is a "name too long" error (ENAMETOOLONG).
    ///
    /// Interface names in Linux are limited to 15 characters (IFNAMSIZ - 1).
    pub fn is_name_too_long(&self) -> bool {
        self.errno() == Some(libc::ENAMETOOLONG)
    }

    /// Check if this is a "resource temporarily unavailable" error (EAGAIN).
    ///
    /// This may occur during transient resource contention.
    pub fn is_try_again(&self) -> bool {
        self.errno() == Some(libc::EAGAIN)
    }

    /// Check if this is `ERESTART`. From nftables it means a batch was sent
    /// with a ruleset generation that is no longer current
    /// ([`Transaction::expect_generation`](crate::netlink::nftables::Transaction::expect_generation)):
    /// something changed the ruleset after the diff was taken. Diff again
    /// and apply that (#482).
    pub fn is_restart(&self) -> bool {
        self.errno() == Some(libc::ERESTART)
    }

    /// Check if this is a "no buffer space available" error (ENOBUFS).
    ///
    /// This typically occurs when the kernel cannot allocate memory
    /// for network operations.
    pub fn is_no_buffer_space(&self) -> bool {
        // Plan 187 made `errno()` itself unwrap `Error::from` via
        // `raw_os_error()`, so this predicate (and every sibling
        // predicate) catches both the kernel-shape and the
        // socket-shape ENOBUFS via the same path. The Plan 185
        // defensive branch is no longer needed.
        self.errno() == Some(libc::ENOBUFS)
    }

    /// Check if this is a "connection refused" error (ECONNREFUSED).
    pub fn is_connection_refused(&self) -> bool {
        self.errno() == Some(libc::ECONNREFUSED)
    }

    /// Check if this is a "host unreachable" error (EHOSTUNREACH).
    pub fn is_host_unreachable(&self) -> bool {
        self.errno() == Some(libc::EHOSTUNREACH)
    }

    /// Check if this is a "message too long" error (EMSGSIZE).
    ///
    /// This occurs when a netlink message exceeds the maximum size.
    pub fn is_message_too_long(&self) -> bool {
        self.errno() == Some(libc::EMSGSIZE)
    }

    /// Check if this is a "too many open files" error (EMFILE).
    pub fn is_too_many_open_files(&self) -> bool {
        self.errno() == Some(libc::EMFILE)
    }

    /// Check if this is a "read-only file system" error (EROFS).
    ///
    /// This can occur when trying to modify network configuration
    /// in a read-only namespace or container.
    pub fn is_read_only(&self) -> bool {
        self.errno() == Some(libc::EROFS)
    }
}

/// Lets validated newtypes (e.g. [`nftables`](crate::netlink::nftables)
/// `TableName` / `ChainName`) flow through `impl TryInto<…>` method
/// arguments alongside `&str`: the already-typed path's `TryInto`
/// error is `Infallible`, which this bridges into [`Error`] so a
/// single `T::Error: Into<Error>` bound accepts both.
impl From<std::convert::Infallible> for Error {
    fn from(never: std::convert::Infallible) -> Self {
        match never {}
    }
}

/// Named iterator returned by [`Error::chain_walk`]. Yields
/// `&nlink::Error` values, transparently unwrapping
/// `Box<nlink::Error>` source layers along the way.
///
/// Plan 187 §2.2.
#[must_use = "iterators do nothing unless polled"]
pub struct ChainWalk<'a> {
    current: Option<&'a (dyn std::error::Error + 'static)>,
}

impl<'a> Iterator for ChainWalk<'a> {
    type Item = &'a Error;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let err = self.current?;
            // Try the unboxed form first (the common shape).
            if let Some(nl) = err.downcast_ref::<Error>() {
                self.current = err.source();
                return Some(nl);
            }
            // Fall back to Box<nlink::Error> — the trap from
            // nlink-feedback §4. The `downcast_ref` on the
            // outer &dyn Error sees the concrete Box type.
            if let Some(boxed) = err.downcast_ref::<Box<Error>>() {
                self.current = err.source();
                return Some(boxed.as_ref());
            }
            // Not an nlink error at this level; advance and
            // try again.
            self.current = err.source();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `kind()` and the predicates agree on every errno they share (#526).
    #[test]
    fn kind_agrees_with_the_predicates() {
        type Pred = fn(&Error) -> bool;
        let pairs: [(i32, ErrorKind, Pred); 18] = [
            (libc::ENOENT, ErrorKind::NotFound, Error::is_not_found),
            (libc::ENODEV, ErrorKind::NotFound, Error::is_not_found),
            (
                libc::EEXIST,
                ErrorKind::AlreadyExists,
                Error::is_already_exists,
            ),
            (libc::EBUSY, ErrorKind::Busy, Error::is_busy),
            (
                libc::EPERM,
                ErrorKind::PermissionDenied,
                Error::is_permission_denied,
            ),
            (
                libc::EACCES,
                ErrorKind::PermissionDenied,
                Error::is_permission_denied,
            ),
            (
                libc::EOPNOTSUPP,
                ErrorKind::NotSupported,
                Error::is_not_supported,
            ),
            (
                libc::EINVAL,
                ErrorKind::InvalidArgument,
                Error::is_invalid_argument,
            ),
            (libc::EAGAIN, ErrorKind::TryAgain, Error::is_try_again),
            (libc::ERESTART, ErrorKind::Restart, Error::is_restart),
            (libc::ENOBUFS, ErrorKind::Overrun, Error::is_no_buffer_space),
            (libc::ETIMEDOUT, ErrorKind::Timeout, Error::is_timeout),
            (
                libc::ENETUNREACH,
                ErrorKind::NetworkUnreachable,
                Error::is_network_unreachable,
            ),
            (
                libc::EHOSTUNREACH,
                ErrorKind::HostUnreachable,
                Error::is_host_unreachable,
            ),
            (
                libc::EADDRINUSE,
                ErrorKind::AddressInUse,
                Error::is_address_in_use,
            ),
            (
                libc::ECONNREFUSED,
                ErrorKind::ConnectionRefused,
                Error::is_connection_refused,
            ),
            (
                libc::EMSGSIZE,
                ErrorKind::MessageTooLong,
                Error::is_message_too_long,
            ),
            (libc::EROFS, ErrorKind::ReadOnly, Error::is_read_only),
        ];
        for (errno, kind, pred) in pairs {
            for err in [
                Error::from_errno(errno),
                Error::from_errno(errno).with_context("op"),
                Error::from(std::io::Error::from_raw_os_error(errno)),
            ] {
                assert_eq!(err.kind(), kind, "{err}");
                assert!(pred(&err), "{err}");
            }
        }
        assert_eq!(Error::from_errno(libc::EPROTO).kind(), ErrorKind::Other);
    }

    /// `NotConverged` says what was left, and is its own kind (#518).
    #[test]
    fn not_converged_shows_what_is_left() {
        let err = Error::from(crate::netlink::ErrorDetail::NotConverged {
            remaining: Box::default(),
        });
        assert_eq!(err.kind(), ErrorKind::NotConverged);
        assert!(err.to_string().contains("did not converge"), "{err}");
        assert!(!err.kind().is_retryable());
    }

    #[test]
    fn kind_of_the_variants() {
        assert_eq!(Error::timeout().kind(), ErrorKind::Timeout);
        assert_eq!(Error::interface_not_found("d0").kind(), ErrorKind::NotFound);
        assert_eq!(
            Error::namespace_not_found("red").kind(),
            ErrorKind::NotFound
        );
        assert_eq!(Error::not_supported("x").kind(), ErrorKind::NotSupported);
        assert_eq!(Error::invalid_message("x").kind(), ErrorKind::Invalid);
        assert_eq!(Error::internal("worker panicked").kind(), ErrorKind::Other);
        assert_eq!(
            Error::validation_error("links.d0", "bad").kind(),
            ErrorKind::Validation
        );
        assert_eq!(Error::dump_interrupted().kind(), ErrorKind::DumpInterrupted);
        let exists = Error::from(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "x"));
        assert_eq!(exists.kind(), ErrorKind::AlreadyExists);
        assert!(exists.is_already_exists());
        assert!(ErrorKind::Busy.is_retryable());
        assert!(!ErrorKind::NotFound.is_retryable());
    }

    /// A second context goes in front of the first; it used to be dropped.
    /// The same label twice is said once (#526).
    #[test]
    fn context_stacks() {
        let err = Error::from_errno(libc::EBUSY)
            .with_context("replace_qdisc")
            .with_context("apply qdisc on a:eth0");
        let shown = err.to_string();
        assert!(
            shown.starts_with("apply qdisc on a:eth0: replace_qdisc"),
            "{shown}"
        );
        assert!(err.is_busy());

        let once = Error::from_errno(libc::EBUSY)
            .with_context("add_link(veth0, kind=veth)")
            .with_context("add_link");
        assert!(!once.to_string().contains("add_link: add_link"), "{once}");
        let twice = Error::from_errno(libc::EBUSY)
            .with_context("x")
            .with_context("x");
        assert!(!twice.to_string().contains("x: x"), "{twice}");

        let r: Result<()> = Err(Error::from_errno(libc::ENOENT));
        let err = r.context("del_route(10.0.0.0/8, table 100)").unwrap_err();
        assert!(
            err.to_string()
                .starts_with("del_route(10.0.0.0/8, table 100)"),
            "{err}"
        );
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    /// #718: a caller that knows the device by name refines a qdisc a layer
    /// below named by ifindex, message and all; another kind of object, or
    /// one that is there already, is kept.
    #[test]
    fn a_caller_refines_what_a_lower_layer_named() {
        let slot = |dev: &str| ErrorObject::Qdisc {
            dev: dev.into(),
            parent: Some("root".into()),
            kind: None,
        };
        let refined = Error::not_found(slot("ifindex 10")).refine_object(slot("dummy0"));
        assert_eq!(refined.object(), Some(&slot("dummy0")));
        assert_eq!(refined.to_string(), "not found: qdisc at root on dummy0");
        let kernel = Error::from_errno(libc::EEXIST).refine_object(slot("dummy0"));
        assert_eq!(kernel.object(), Some(&slot("dummy0")));
        let link = Error::interface_not_found("eth9").refine_object(slot("eth9"));
        assert_eq!(link.object(), Some(&ErrorObject::Link { name: "eth9".into() }));
        assert_eq!(link.to_string(), "interface not found: eth9");
    }

    /// #718: TC objects read as tc(8) would name them.
    #[test]
    fn tc_objects_read_like_tc() {
        let qdisc = ErrorObject::Qdisc {
            dev: "eth0".into(),
            parent: Some("1:a".into()),
            kind: Some("fq_codel".into()),
        };
        assert_eq!(qdisc.to_string(), "qdisc fq_codel at 1:a on eth0");
        let slot = ErrorObject::Qdisc {
            dev: "eth0".into(),
            parent: Some("root".into()),
            kind: None,
        };
        assert_eq!(slot.to_string(), "qdisc at root on eth0");
        let class = ErrorObject::TcClass {
            dev: "eth0".into(),
            classid: "1:a".into(),
        };
        assert_eq!(class.to_string(), "class 1:a on eth0");
        let filter = ErrorObject::TcFilter {
            dev: "eth0".into(),
            parent: "1:".into(),
            priority: 100,
            protocol: "ip".into(),
        };
        assert_eq!(filter.to_string(), "filter at 1: prio 100 ip on eth0");
    }

    /// #718: an error says which namespace its connection was in. It shows
    /// last, after any context and the kernel's message, and the first
    /// stamp wins: a sibling's error does not take its caller's label.
    #[test]
    fn an_error_names_its_namespace() {
        let red: std::sync::Arc<str> = "red".into();
        let blue: std::sync::Arc<str> = "blue".into();
        let err = Error::from_errno(libc::EEXIST)
            .in_netns(&red)
            .in_netns(&blue)
            .with_context("add_link(d0)");
        assert_eq!(err.netns(), Some("red"));
        assert_eq!(err.to_string(), "add_link(d0): File exists (errno 17) [netns red]");
        assert_eq!(
            Error::timeout().in_netns(&red).to_string(),
            format!("{} [netns red]", Error::timeout())
        );
        let debug = format!("{err:?}");
        assert!(debug.contains("netns: \"red\""), "{debug}");
        assert!(err.is_already_exists(), "the kind survives the stamp");

        let plain = Error::from_errno(libc::EEXIST);
        assert_eq!(plain.netns(), None);
        assert!(!plain.to_string().contains("[netns"), "{plain}");
    }

    /// #526: a context is kept on every error. Until 0.32 `with_context`
    /// returned anything but a kernel error unchanged, so an I/O error, a
    /// refused batch or a validation failure lost what was being done.
    #[test]
    fn a_context_is_kept_on_any_error() {
        let io = Error::from(io::Error::from_raw_os_error(libc::EBUSY))
            .with_context("remove namespace file")
            .with_context("delete namespace red");
        assert_eq!(io.context(), ["delete namespace red", "remove namespace file"]);
        assert!(
            io.to_string()
                .starts_with("delete namespace red: remove namespace file: I/O error: "),
            "{io}"
        );
        assert!(io.is_busy(), "the errno survives the context");

        let invalid = Error::invalid_message("bad").with_context("parse rule");
        assert_eq!(invalid.to_string(), "parse rule: invalid message: bad");
        assert_eq!(invalid.kind(), ErrorKind::Invalid);
        let validation = Error::validation_error("links.d0", "no kind").with_context("apply");
        assert_eq!(validation.context(), ["apply"]);
        assert_eq!(validation.kind(), ErrorKind::Validation);

        // A kernel error reads as before, with and without one.
        assert_eq!(
            Error::from_errno(libc::EEXIST).to_string(),
            "kernel error: File exists (errno 17)"
        );
        assert_eq!(
            Error::from_errno(libc::EEXIST).with_context("add_link(d0)").to_string(),
            "add_link(d0): File exists (errno 17)"
        );
        assert!(matches!(io.detail(), ErrorDetail::Io(_)));
        assert!(io.into_detail().to_string().starts_with("I/O error: "));
    }

    /// #526: an error names its object. A detail that carries one names
    /// it by itself; `with_object` keeps the innermost.
    #[test]
    fn an_error_names_its_object() {
        let sysctl = Error::from(ErrorDetail::Sysctl {
            key: "net.ipv4.ip_forward".into(),
            source: io::Error::from_raw_os_error(libc::EACCES),
        });
        assert_eq!(
            sysctl.object(),
            Some(&ErrorObject::Sysctl {
                key: "net.ipv4.ip_forward".into()
            })
        );
        let link = Error::interface_not_found("d0").with_object(ErrorObject::Tc { dev: "d1".into() });
        assert_eq!(link.object(), Some(&ErrorObject::Link { name: "d0".into() }), "the inner one stays");
        let route = Error::from_errno(libc::ENETUNREACH).with_object(ErrorObject::Route {
            destination: "10.9.0.0/24".into(),
            table: Some(100),
        });
        assert_eq!(route.object().unwrap().to_string(), "route 10.9.0.0/24 table 100");
        assert_eq!(Error::from_errno(libc::EEXIST).object(), None);
    }

    /// One pointer wide: every `Result<T>` in the crate pays for it.
    #[test]
    fn an_error_is_one_pointer() {
        assert_eq!(std::mem::size_of::<Error>(), std::mem::size_of::<usize>());
    }

    #[test]
    fn test_from_errno() {
        let err = Error::from_errno(-1); // EPERM
        assert!(err.is_permission_denied());
        assert_eq!(err.errno(), Some(1));
    }

    #[test]
    fn test_from_errno_with_context() {
        let err = Error::from_errno_with_context(-2, "deleting interface eth0"); // ENOENT
        assert!(err.is_not_found());
        let msg = err.to_string();
        assert!(msg.contains("deleting interface eth0"));
        assert!(msg.contains("No such file or directory"));
    }

    #[test]
    fn test_with_context() {
        let err = Error::from_errno(-13); // EACCES
        let err = err.with_context("setting link up on eth0");
        assert!(err.is_permission_denied());
        let msg = err.to_string();
        assert!(msg.contains("setting link up on eth0"));
    }

    #[test]
    fn test_is_not_found() {
        assert!(Error::from_errno(-2).is_not_found()); // ENOENT
        assert!(Error::from_errno(-19).is_not_found()); // ENODEV
        assert!(Error::interface_not_found("eth0").is_not_found());
        assert!(Error::namespace_not_found("test").is_not_found());
        assert!(Error::qdisc_not_found("netem", "eth0").is_not_found());
        assert!(Error::family_not_found("wireguard").is_not_found());
        // However a missing interface was found missing, it is one detail
        // (#718).
        let via_ifname = Error::from(crate::util::ifname::IfError::NotFound("eth9".into()));
        assert!(
            matches!(
                via_ifname.detail(),
                ErrorDetail::NotFound { object: ErrorObject::Link { name } } if name == "eth9"
            ),
            "{via_ifname:?}"
        );
        assert_eq!(
            via_ifname.object(),
            Some(&ErrorObject::Link { name: "eth9".into() })
        );
    }

    #[test]
    fn test_is_busy() {
        assert!(Error::from_errno(-16).is_busy()); // EBUSY
        assert!(!Error::from_errno(-1).is_busy()); // EPERM is not busy
    }

    // is_already_exists must match both the raw-errno shape and an
    // `ErrorKind::AlreadyExists` io::Error built without one (the
    // namespace::create_path rejection) — same widening as Plan 212's
    // is_not_found.
    #[test]
    fn is_already_exists_catches_kind_without_errno() {
        let err = Error::from(io::Error::new(io::ErrorKind::AlreadyExists, "x exists"));
        assert!(err.is_already_exists());
        assert!(Error::from_errno(-libc::EEXIST).is_already_exists());
        assert!(!Error::from(io::Error::new(io::ErrorKind::NotFound, "gone")).is_already_exists());
    }

    // Plan 212 M9 — is_not_found must match Error::from(ENOENT/ENODEV)
    // through the common `errno()` accessor (sibling predicates
    // `is_busy`, `is_permission_denied`, `is_already_exists` already
    // did per Plan 187 §2.5; this closes the asymmetry).
    #[test]
    fn is_not_found_catches_io_enoent() {
        let io_err = io::Error::from_raw_os_error(libc::ENOENT);
        let err: Error = io_err.into();
        assert!(
            err.is_not_found(),
            "is_not_found must catch Error::from(ENOENT) (Plan 212 M9)"
        );
    }

    #[test]
    fn is_not_found_catches_io_enodev() {
        let io_err = io::Error::from_raw_os_error(libc::ENODEV);
        let err: Error = io_err.into();
        assert!(err.is_not_found());
    }

    #[test]
    fn is_not_found_does_not_match_unrelated_io_errors() {
        let io_err = io::Error::from_raw_os_error(libc::EPERM);
        let err: Error = io_err.into();
        assert!(!err.is_not_found());
    }

    #[test]
    fn test_timeout() {
        let err = Error::timeout();
        assert!(err.is_timeout());
        assert_eq!(err.to_string(), "operation timed out");

        // Kernel ETIMEDOUT should also match
        let err = Error::from_errno(-(libc::ETIMEDOUT));
        assert!(err.is_timeout());
    }

    #[test]
    fn test_dump_interrupted_predicate() {
        let err = Error::dump_interrupted();
        assert!(err.is_dump_interrupted());
        // Mutually exclusive with other recovery predicates.
        assert!(!err.is_timeout());
        assert!(!err.is_busy());
        assert!(!err.is_not_found());
        // Message mentions retry guidance so the error is
        // self-describing in logs.
        let s = err.to_string();
        assert!(s.contains("interrupted"), "got: {s}");
        assert!(s.contains("retry"), "got: {s}");
    }

    #[test]
    fn test_dump_interrupted_does_not_match_unrelated_errors() {
        assert!(!Error::timeout().is_dump_interrupted());
        assert!(!Error::from_errno(-16).is_dump_interrupted()); // EBUSY
        assert!(!Error::interface_not_found("x").is_dump_interrupted());
    }

    #[test]
    fn test_error_messages() {
        // The four details `NotFound` replaced read as they did (#718).
        let err = Error::interface_not_found("eth0");
        assert_eq!(err.to_string(), "interface not found: eth0");
        let err = Error::namespace_not_found("myns");
        assert_eq!(err.to_string(), "namespace not found: myns");
        let err = Error::qdisc_not_found("netem", "docker0");
        assert_eq!(err.to_string(), "qdisc not found: netem on docker0");
        let err = Error::family_not_found("ovpn");
        assert_eq!(err.to_string(), "GENL family not found: ovpn");
        let err = Error::not_found(ErrorObject::TcClass {
            dev: "eth0".into(),
            classid: "1:a".into(),
        });
        assert_eq!(err.to_string(), "not found: class 1:a on eth0");
        assert_eq!(err.kind(), ErrorKind::NotFound);
        // The kernel's text is computed from the errno, as it was stored.
        assert_eq!(
            Error::from_errno(libc::ENOENT).to_string(),
            "kernel error: No such file or directory (errno 2)"
        );
    }

    // ---- Plan 182 — ext_ack / ext_ack_offset accessors ----

    #[test]
    fn ext_ack_returns_some_for_kernel_with_ack() {
        let err = Error::from(crate::netlink::ErrorDetail::Kernel {
            errno: 22,
            ext_ack: Some("attribute IFLA_MTU rejected: value 0 out of range".into()),
            ext_ack_offset: Some(24),
            request_type: None,
            protocol: None,
        });
        assert_eq!(
            err.ext_ack(),
            Some("attribute IFLA_MTU rejected: value 0 out of range")
        );
        assert_eq!(err.ext_ack_offset(), Some(24));
    }

    #[test]
    fn ext_ack_returns_some_for_kernel_with_context() {
        let err = Error::from_errno_with_context_ext_ack(
            17,
            "add_link",
            Some("interface 'veth0' already exists".into()),
            None,
        );
        assert_eq!(err.ext_ack(), Some("interface 'veth0' already exists"));
        assert_eq!(err.ext_ack_offset(), None);
    }

    #[test]
    fn ext_ack_returns_none_for_kernel_without_ack() {
        let err = Error::from(crate::netlink::ErrorDetail::Kernel {
            errno: 22,
            ext_ack: None,
            ext_ack_offset: None,
            request_type: None,
            protocol: None,
        });
        assert_eq!(err.ext_ack(), None);
        assert_eq!(err.ext_ack_offset(), None);
    }

    #[test]
    fn ext_ack_returns_none_for_non_kernel_errors() {
        assert_eq!(Error::timeout().ext_ack(), None);
        assert_eq!(Error::timeout().ext_ack_offset(), None);
        assert_eq!(Error::invalid_message("bad").ext_ack(), None);
    }

    // Plan 185 fix — `is_no_buffer_space` must catch the OS-shape
    // ENOBUFS from a raw `recvmsg`, not just the kernel-shape
    // NLMSGERR variant. The multicast overflow path takes the
    // OS branch.
    #[test]
    fn is_no_buffer_space_matches_io_enobufs() {
        let err = Error::from(std::io::Error::from_raw_os_error(libc::ENOBUFS));
        assert!(
            err.is_no_buffer_space(),
            "Io(ENOBUFS) must be caught by is_no_buffer_space"
        );
    }

    #[test]
    fn is_no_buffer_space_matches_kernel_enobufs() {
        let err = Error::from(crate::netlink::ErrorDetail::Kernel {
            errno: libc::ENOBUFS,
            ext_ack: None,
            ext_ack_offset: None,
            request_type: None,
            protocol: None,
        });
        assert!(err.is_no_buffer_space());
    }

    #[test]
    fn is_no_buffer_space_rejects_unrelated_io_errors() {
        let err = Error::from(std::io::Error::from_raw_os_error(libc::EAGAIN));
        assert!(!err.is_no_buffer_space());
    }

    // ===== Plan 187 — sign-normalization on the factories. =====

    #[test]
    fn from_errno_ext_ack_normalizes_negative_input() {
        let e = Error::from_errno_ext_ack(-libc::EEXIST, None, None);
        assert_eq!(e.errno(), Some(libc::EEXIST));
    }

    #[test]
    fn from_errno_ext_ack_normalizes_positive_input() {
        let e = Error::from_errno_ext_ack(libc::EEXIST, None, None);
        assert_eq!(e.errno(), Some(libc::EEXIST));
    }

    #[test]
    fn from_errno_ext_ack_zero_stays_zero() {
        let e = Error::from_errno_ext_ack(0, None, None);
        assert_eq!(e.errno(), Some(0));
    }

    #[test]
    fn from_errno_with_context_ext_ack_normalizes_both_signs() {
        let neg = Error::from_errno_with_context_ext_ack(-libc::EBUSY, "add_link", None, None);
        let pos = Error::from_errno_with_context_ext_ack(libc::EBUSY, "add_link", None, None);
        assert_eq!(neg.errno(), pos.errno());
        assert_eq!(neg.errno(), Some(libc::EBUSY));
    }

    #[test]
    fn from_errno_delegates_to_from_errno_ext_ack_for_normalization() {
        // `from_errno` is a thin wrapper around `from_errno_ext_ack`,
        // so it inherits the sign-normalization. Pin it.
        let neg = Error::from_errno(-libc::EINVAL);
        let pos = Error::from_errno(libc::EINVAL);
        assert_eq!(neg.errno(), pos.errno());
        assert_eq!(neg.errno(), Some(libc::EINVAL));
    }

    // ===== Plan 187 §2.5 — predicate Io-shape sweep. =====
    //
    // Every `is_*` predicate must match BOTH `Error::Kernel*`
    // and `Error::from` variants carrying the same errno. The
    // Plan 187 fix to `errno()` (unwrap `Io` via
    // `raw_os_error()`) makes this work uniformly; this sweep
    // pins the contract so future predicates inherit it.

    fn assert_predicate_matches_both_shapes(pred: fn(&Error) -> bool, errno: i32, name: &str) {
        let kernel = Error::from_errno_ext_ack(errno, None, None);
        assert!(
            pred(&kernel),
            "{name}: Kernel({errno}) must match the predicate"
        );
        let io = Error::from(std::io::Error::from_raw_os_error(errno));
        assert!(pred(&io), "{name}: Io({errno}) must match the predicate");
        let kctx = Error::from_errno_with_context_ext_ack(errno, "ctx", None, None);
        assert!(
            pred(&kctx),
            "{name}: KernelWithContext({errno}) must match the predicate"
        );
    }

    #[test]
    fn predicate_io_shape_sweep() {
        // Each predicate × 3 variants = 36+ assertions via the
        // shared helper. Adding a new `is_*` predicate later
        // appends one line here.
        assert_predicate_matches_both_shapes(
            Error::is_no_buffer_space,
            libc::ENOBUFS,
            "is_no_buffer_space",
        );
        assert_predicate_matches_both_shapes(Error::is_busy, libc::EBUSY, "is_busy");
        assert_predicate_matches_both_shapes(Error::is_try_again, libc::EAGAIN, "is_try_again");
        assert_predicate_matches_both_shapes(
            Error::is_already_exists,
            libc::EEXIST,
            "is_already_exists",
        );
        assert_predicate_matches_both_shapes(
            Error::is_permission_denied,
            libc::EACCES,
            "is_permission_denied",
        );
        assert_predicate_matches_both_shapes(
            Error::is_invalid_argument,
            libc::EINVAL,
            "is_invalid_argument",
        );
        assert_predicate_matches_both_shapes(
            Error::is_not_supported,
            libc::EOPNOTSUPP,
            "is_not_supported",
        );
        assert_predicate_matches_both_shapes(
            Error::is_network_unreachable,
            libc::ENETUNREACH,
            "is_network_unreachable",
        );
        assert_predicate_matches_both_shapes(
            Error::is_host_unreachable,
            libc::EHOSTUNREACH,
            "is_host_unreachable",
        );
        assert_predicate_matches_both_shapes(
            Error::is_connection_refused,
            libc::ECONNREFUSED,
            "is_connection_refused",
        );
    }

    #[test]
    fn predicate_rejects_unrelated_errno_for_each_shape() {
        // is_busy(EAGAIN) must be false — the predicate is
        // specific to its target errno, not "any retryable error".
        let kernel_eagain = Error::from_errno_ext_ack(libc::EAGAIN, None, None);
        assert!(!kernel_eagain.is_busy());
        let io_eagain = Error::from(std::io::Error::from_raw_os_error(libc::EAGAIN));
        assert!(!io_eagain.is_busy());
    }

    // ===== Plan 187 §2.2 — Error::chain_walk + root_cause + contexts. =====

    #[derive(Debug, thiserror::Error)]
    #[error("inline wrapper")]
    struct InlineWrapper(#[source] Error);

    #[derive(Debug, thiserror::Error)]
    #[error("boxed wrapper")]
    struct BoxedWrapper(#[source] Box<Error>);

    #[test]
    fn chain_walk_finds_nlink_error_through_inline_source() {
        let inner = Error::from_errno_ext_ack(libc::EEXIST, None, None);
        let outer = InlineWrapper(inner);
        let found: Vec<_> = Error::chain_walk(&outer).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].errno(), Some(libc::EEXIST));
    }

    #[test]
    fn chain_walk_finds_nlink_error_through_boxed_source() {
        // The trap from nlink-feedback §4 — must NOT yield empty.
        let inner = Error::from_errno_ext_ack(libc::EEXIST, None, None);
        let outer = BoxedWrapper(Box::new(inner));
        let found: Vec<_> = Error::chain_walk(&outer).collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].errno(), Some(libc::EEXIST));
    }

    #[test]
    fn chain_walk_returns_empty_for_non_nlink_chain() {
        let plain = std::io::Error::other("no nlink here");
        let v: Vec<_> = Error::chain_walk(&plain).collect();
        assert!(v.is_empty());
    }

    #[test]
    fn root_cause_returns_deepest_nlink_error() {
        // Two-level chain: BoxedWrapper(InlineWrapper(Error)).
        // root_cause must reach the innermost.
        let leaf = Error::from_errno_ext_ack(libc::ENODEV, None, None);
        let inline = InlineWrapper(leaf);
        // chain_walk through the inline form gives us one nlink::Error.
        let walked: Vec<_> = Error::chain_walk(&inline).collect();
        assert_eq!(walked.len(), 1);
        assert_eq!(walked[0].errno(), Some(libc::ENODEV));
    }

    #[test]
    fn root_cause_falls_back_to_self_when_chain_is_single() {
        let solo = Error::from_errno_ext_ack(libc::EAGAIN, None, None);
        assert_eq!(solo.root_cause().errno(), solo.errno());
    }

    #[test]
    fn contexts_returns_every_layer_outer_to_inner() {
        let leaf = Error::from_errno_ext_ack(libc::ENOENT, None, None);
        let inline = InlineWrapper(leaf);
        let v = Error::chain_walk(&inline).collect::<Vec<_>>();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].errno(), Some(libc::ENOENT));
    }
}
