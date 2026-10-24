//! WireGuard type definitions.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Size of a WireGuard key in bytes.
pub const WG_KEY_LEN: usize = 32;

/// WireGuard device information.
#[derive(Clone, Default)]
pub struct WgDevice {
    /// Interface index.
    pub ifindex: Option<u32>,
    /// Interface name.
    pub ifname: Option<String>,
    /// Private key. Returned by the kernel only to callers holding
    /// `CAP_NET_ADMIN` in the device's netns (as `wg showconf` does); `None`
    /// for unprivileged callers or a device with no key configured (the
    /// kernel's all-zeros sentinel is normalized to `None`).
    pub private_key: Option<[u8; WG_KEY_LEN]>,
    /// Public key (derived from private key). `None` for a device with no key
    /// configured (the kernel's all-zeros sentinel is normalized to `None`).
    pub public_key: Option<[u8; WG_KEY_LEN]>,
    /// UDP listen port (0 = kernel chooses).
    pub listen_port: Option<u16>,
    /// Firewall mark for outgoing packets.
    pub fwmark: Option<u32>,
    /// Configured peers.
    pub peers: Vec<WgPeer>,
}

impl std::fmt::Debug for WgDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("WgDevice")
            .field("ifindex", &self.ifindex)
            .field("ifname", &self.ifname)
            .field(
                "private_key",
                &self
                    .private_key
                    .as_ref()
                    .map(|k| crate::util::SecretBytes(k.as_ref())),
            )
            .field("public_key", &self.public_key)
            .field("listen_port", &self.listen_port)
            .field("fwmark", &self.fwmark)
            .field("peers", &self.peers)
            .finish()
    }
}

impl WgDevice {
    /// Create a new empty device.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for setting device configuration.
    pub fn builder() -> WgDeviceBuilder {
        WgDeviceBuilder::new()
    }
}

/// Builder for WgDevice configuration.
#[derive(Clone, Default)]
#[must_use = "builders do nothing unless used"]
pub struct WgDeviceBuilder {
    private_key: Option<[u8; WG_KEY_LEN]>,
    listen_port: Option<u16>,
    fwmark: Option<u32>,
    replace_peers: bool,
    peers: Vec<WgPeerBuilder>,
}

impl std::fmt::Debug for WgDeviceBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("WgDeviceBuilder")
            .field(
                "private_key",
                &self
                    .private_key
                    .as_ref()
                    .map(|k| crate::util::SecretBytes(k.as_ref())),
            )
            .field("listen_port", &self.listen_port)
            .field("fwmark", &self.fwmark)
            .field("replace_peers", &self.replace_peers)
            .field("peers", &self.peers)
            .finish()
    }
}

impl WgDeviceBuilder {
    /// Create a new device builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the private key.
    pub fn private_key(mut self, key: [u8; WG_KEY_LEN]) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Set the listen port.
    pub fn listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    /// Set the firewall mark.
    pub fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    /// Replace all existing peers (instead of merging).
    pub fn replace_peers(mut self) -> Self {
        self.replace_peers = true;
        self
    }

    /// Add a peer to configure.
    pub fn peer(mut self, peer: WgPeerBuilder) -> Self {
        self.peers.push(peer);
        self
    }

    /// Check if replace_peers flag is set.
    pub fn has_replace_peers(&self) -> bool {
        self.replace_peers
    }

    /// Get the private key if set.
    pub fn get_private_key(&self) -> Option<&[u8; WG_KEY_LEN]> {
        self.private_key.as_ref()
    }

    /// Get the listen port if set.
    pub fn get_listen_port(&self) -> Option<u16> {
        self.listen_port
    }

    /// Get the fwmark if set.
    pub fn get_fwmark(&self) -> Option<u32> {
        self.fwmark
    }

    /// Get the peers to configure.
    pub fn get_peers(&self) -> &[WgPeerBuilder] {
        &self.peers
    }
}

/// WireGuard peer information.
#[derive(Clone, Default)]
pub struct WgPeer {
    /// Peer's public key (identifies the peer).
    pub public_key: [u8; WG_KEY_LEN],
    /// Optional preshared key for post-quantum resistance.
    pub preshared_key: Option<[u8; WG_KEY_LEN]>,
    /// Peer's endpoint (IP:port).
    pub endpoint: Option<SocketAddr>,
    /// Persistent keepalive interval in seconds (0 = disabled).
    pub persistent_keepalive: Option<u16>,
    /// Last successful handshake time.
    pub last_handshake: Option<SystemTime>,
    /// Bytes received from this peer.
    pub rx_bytes: u64,
    /// Bytes sent to this peer.
    pub tx_bytes: u64,
    /// Allowed IP ranges for this peer.
    pub allowed_ips: Vec<AllowedIp>,
    /// Protocol version (typically 1).
    pub protocol_version: Option<u32>,
}

impl std::fmt::Debug for WgPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("WgPeer")
            .field("public_key", &self.public_key)
            .field(
                "preshared_key",
                &self
                    .preshared_key
                    .as_ref()
                    .map(|k| crate::util::SecretBytes(k.as_ref())),
            )
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("last_handshake", &self.last_handshake)
            .field("rx_bytes", &self.rx_bytes)
            .field("tx_bytes", &self.tx_bytes)
            .field("allowed_ips", &self.allowed_ips)
            .field("protocol_version", &self.protocol_version)
            .finish()
    }
}

impl WgPeer {
    /// Fold a dump continuation for the same public key into this peer.
    ///
    /// The kernel re-emits `WGPEER_A_PUBLIC_KEY` on the continuation and
    /// carries only the remaining `allowed_ips`; the scalars were sent
    /// with the first chunk. So the allowed IPs accumulate, and every
    /// other field is taken from the continuation only if it actually
    /// carries one — a zeroed `rx_bytes` in a continuation means "not
    /// repeated", not "zero" (#277).
    pub(crate) fn merge_continuation(&mut self, other: Self) {
        self.allowed_ips.extend(other.allowed_ips);
        if other.preshared_key.is_some() {
            self.preshared_key = other.preshared_key;
        }
        if other.endpoint.is_some() {
            self.endpoint = other.endpoint;
        }
        if other.persistent_keepalive.is_some() {
            self.persistent_keepalive = other.persistent_keepalive;
        }
        if other.last_handshake.is_some() {
            self.last_handshake = other.last_handshake;
        }
        if other.protocol_version.is_some() {
            self.protocol_version = other.protocol_version;
        }
        if other.rx_bytes != 0 {
            self.rx_bytes = other.rx_bytes;
        }
        if other.tx_bytes != 0 {
            self.tx_bytes = other.tx_bytes;
        }
    }

    /// Create a new peer with the given public key.
    pub fn new(public_key: [u8; WG_KEY_LEN]) -> Self {
        Self {
            public_key,
            ..Default::default()
        }
    }

    /// Create a builder for this peer.
    pub fn builder(public_key: [u8; WG_KEY_LEN]) -> WgPeerBuilder {
        WgPeerBuilder::new(public_key)
    }

    /// Get the duration since last handshake.
    pub fn time_since_handshake(&self) -> Option<Duration> {
        self.last_handshake
            .and_then(|t| SystemTime::now().duration_since(t).ok())
    }
}

/// Peer flags for SET_DEVICE operations.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WgPeerFlags {
    /// Remove this peer.
    RemoveMe = 1 << 0,
    /// Replace all allowed IPs (instead of adding).
    ReplaceAllowedIps = 1 << 1,
    /// Change the peer only if it already exists: a `SET_DEVICE` that
    /// names a peer the device does not have skips it, silently, instead
    /// of creating it (`WGPEER_F_UPDATE_ONLY`). nlink's builders do not
    /// set it.
    UpdateOnly = 1 << 2,
}

/// Builder for configuring a WireGuard peer.
#[derive(Clone)]
#[must_use = "builders do nothing unless used"]
pub struct WgPeerBuilder {
    public_key: [u8; WG_KEY_LEN],
    preshared_key: Option<[u8; WG_KEY_LEN]>,
    endpoint: Option<SocketAddr>,
    persistent_keepalive: Option<u16>,
    allowed_ips: Vec<AllowedIp>,
    removed_allowed_ips: Vec<AllowedIp>,
    flags: u32,
}

impl std::fmt::Debug for WgPeerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("WgPeerBuilder")
            .field("public_key", &self.public_key)
            .field(
                "preshared_key",
                &self
                    .preshared_key
                    .as_ref()
                    .map(|k| crate::util::SecretBytes(k.as_ref())),
            )
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("allowed_ips", &self.allowed_ips)
            .field("removed_allowed_ips", &self.removed_allowed_ips)
            .field("flags", &self.flags)
            .finish()
    }
}

impl WgPeerBuilder {
    /// Create a new peer builder with the given public key.
    pub fn new(public_key: [u8; WG_KEY_LEN]) -> Self {
        Self {
            public_key,
            preshared_key: None,
            endpoint: None,
            persistent_keepalive: None,
            allowed_ips: Vec::new(),
            removed_allowed_ips: Vec::new(),
            flags: 0,
        }
    }

    /// Remove one allowed-IP prefix from the peer, leaving the others —
    /// `WGALLOWEDIP_F_REMOVE_ME`, kernel 6.16+ (#529). An older kernel
    /// refuses the message (`EINVAL`); see
    /// [`allowed_ip_removal_supported`](crate::netlink::Connection::allowed_ip_removal_supported).
    /// Unverified on a kernel that has it: this one is 6.12.
    pub fn remove_allowed_ip(mut self, ip: AllowedIp) -> Self {
        self.removed_allowed_ips.push(ip);
        self
    }

    /// The prefixes to remove.
    pub fn get_removed_allowed_ips(&self) -> &[AllowedIp] {
        &self.removed_allowed_ips
    }

    /// Change the peer only if the device has it (`WGPEER_F_UPDATE_ONLY`).
    pub fn update_only(mut self) -> Self {
        self.flags |= WgPeerFlags::UpdateOnly as u32;
        self
    }

    /// Every allowed-IP entry the message carries: the additions, then
    /// the removals (`true`).
    pub(crate) fn allowed_ip_entries(&self) -> Vec<(AllowedIp, bool)> {
        self.allowed_ips
            .iter()
            .map(|ip| (*ip, false))
            .chain(self.removed_allowed_ips.iter().map(|ip| (*ip, true)))
            .collect()
    }

    /// Set the preshared key.
    pub fn preshared_key(mut self, key: [u8; WG_KEY_LEN]) -> Self {
        self.preshared_key = Some(key);
        self
    }

    /// Set the endpoint address.
    pub fn endpoint(mut self, addr: SocketAddr) -> Self {
        self.endpoint = Some(addr);
        self
    }

    /// Set the persistent keepalive interval in seconds.
    pub fn persistent_keepalive(mut self, interval: u16) -> Self {
        self.persistent_keepalive = Some(interval);
        self
    }

    /// Add an allowed IP range.
    pub fn allowed_ip(mut self, ip: AllowedIp) -> Self {
        self.allowed_ips.push(ip);
        self
    }

    /// Add multiple allowed IP ranges.
    pub fn allowed_ips(mut self, ips: impl IntoIterator<Item = AllowedIp>) -> Self {
        self.allowed_ips.extend(ips);
        self
    }

    /// Replace all existing allowed IPs instead of adding.
    pub fn replace_allowed_ips(mut self) -> Self {
        self.flags |= WgPeerFlags::ReplaceAllowedIps as u32;
        self
    }

    /// Mark this peer for removal.
    pub fn remove(mut self) -> Self {
        self.flags |= WgPeerFlags::RemoveMe as u32;
        self
    }

    /// Get the public key.
    pub fn get_public_key(&self) -> &[u8; WG_KEY_LEN] {
        &self.public_key
    }

    /// Get the preshared key if set.
    pub fn get_preshared_key(&self) -> Option<&[u8; WG_KEY_LEN]> {
        self.preshared_key.as_ref()
    }

    /// Get the endpoint if set.
    pub fn get_endpoint(&self) -> Option<&SocketAddr> {
        self.endpoint.as_ref()
    }

    /// Get the persistent keepalive interval if set.
    pub fn get_persistent_keepalive(&self) -> Option<u16> {
        self.persistent_keepalive
    }

    /// Get the allowed IPs.
    pub fn get_allowed_ips(&self) -> &[AllowedIp] {
        &self.allowed_ips
    }

    /// Get the flags.
    pub fn get_flags(&self) -> u32 {
        self.flags
    }
}

/// An allowed IP range for a WireGuard peer.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowedIp {
    /// IP address (network portion).
    pub addr: IpAddr,
    /// CIDR prefix length.
    pub cidr: u8,
}

impl AllowedIp {
    /// Create an IPv4 allowed IP range.
    pub fn v4(addr: Ipv4Addr, cidr: u8) -> Self {
        Self {
            addr: IpAddr::V4(addr),
            cidr: cidr.min(32),
        }
    }

    /// Create an IPv6 allowed IP range.
    pub fn v6(addr: Ipv6Addr, cidr: u8) -> Self {
        Self {
            addr: IpAddr::V6(addr),
            cidr: cidr.min(128),
        }
    }

    /// Get the address family (AF_INET or AF_INET6).
    pub fn family(&self) -> u16 {
        match self.addr {
            IpAddr::V4(_) => libc::AF_INET as u16,
            IpAddr::V6(_) => libc::AF_INET6 as u16,
        }
    }

    /// Get the address bytes.
    pub fn addr_bytes(&self) -> Vec<u8> {
        match self.addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        }
    }
}

impl std::fmt::Display for AllowedIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.cidr)
    }
}

/// Parse a timespec from WireGuard's last_handshake attribute.
///
/// The kernel sends this as two i64 values: seconds and nanoseconds.
///
/// Returns `None` on any malformed input: short buffer, the
/// kernel's documented `(0, 0)` no-handshake sentinel, negative
/// seconds, out-of-range nanoseconds, or far-future overflow.
///
/// # Plan 225 — robustness
///
/// Pre-fix this did `Duration::new(secs as u64, nsecs as u32)`
/// followed by `UNIX_EPOCH + duration`, which panicked in
/// release mode on negative `secs` (the widen to `u64` produces
/// a huge unsigned value; the `SystemTime + Duration` add
/// overflowed). One malformed kernel frame killed the entire
/// `watch()` task, violating CLAUDE.md `## Parser robustness`
/// rule 3 (recoverable per-message parse failures).
///
/// The function's contract was always `Option<SystemTime>`
/// with `None` for malformed input — the panic violated the
/// contract. The set of inputs returning `None` is strictly
/// broader post-fix; no caller needs to change.
pub fn parse_timespec(data: &[u8]) -> Option<SystemTime> {
    if data.len() < 16 {
        return None;
    }

    let secs = i64::from_ne_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let nsecs = i64::from_ne_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    if secs == 0 && nsecs == 0 {
        return None; // No handshake yet — documented sentinel.
    }

    // Reject impossible/garbage timestamps. Pre-1970 makes no
    // sense for a WireGuard last-handshake. Out-of-range nsecs
    // are kernel-side garbage; `Duration::new` would normalize
    // them but the carry can re-overflow secs.
    if secs < 0 {
        return None;
    }
    if !(0..1_000_000_000).contains(&nsecs) {
        return None;
    }

    // Safe to widen: secs is non-negative, nsecs is in
    // [0, 10^9). `Duration::new` cannot panic here.
    let duration = Duration::new(secs as u64, nsecs as u32);

    // `SystemTime::checked_add` returns None on overflow rather
    // than panicking — required by the function's contract.
    UNIX_EPOCH.checked_add(duration)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_ip_v4() {
        let ip = AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 8);
        assert_eq!(ip.family(), libc::AF_INET as u16);
        assert_eq!(ip.cidr, 8);
        assert_eq!(ip.addr_bytes(), vec![10, 0, 0, 0]);
        assert_eq!(ip.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn test_allowed_ip_v6() {
        let ip = AllowedIp::v6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 64);
        assert_eq!(ip.family(), libc::AF_INET6 as u16);
        assert_eq!(ip.cidr, 64);
        assert_eq!(ip.to_string(), "fd00::/64");
    }

    #[test]
    fn test_wg_device_builder() {
        let key = [1u8; 32];
        let builder = WgDeviceBuilder::new()
            .private_key(key)
            .listen_port(51820)
            .fwmark(100);

        assert_eq!(builder.get_private_key(), Some(&key));
        assert_eq!(builder.get_listen_port(), Some(51820));
        assert_eq!(builder.get_fwmark(), Some(100));
    }

    #[test]
    fn test_wg_peer_builder() {
        let pubkey = [2u8; 32];
        let builder = WgPeerBuilder::new(pubkey)
            .persistent_keepalive(25)
            .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
            .replace_allowed_ips();

        assert_eq!(builder.get_public_key(), &pubkey);
        assert_eq!(builder.get_persistent_keepalive(), Some(25));
        assert_eq!(builder.get_allowed_ips().len(), 1);
        assert!(builder.get_flags() & (WgPeerFlags::ReplaceAllowedIps as u32) != 0);
    }

    #[test]
    fn test_parse_timespec() {
        // Zero timespec (no handshake)
        let data = [0u8; 16];
        assert!(parse_timespec(&data).is_none());

        // Valid timespec: 1609459200 seconds (2021-01-01 00:00:00 UTC)
        let mut data = [0u8; 16];
        data[0..8].copy_from_slice(&1609459200i64.to_ne_bytes());
        let time = parse_timespec(&data).unwrap();
        let expected = UNIX_EPOCH + Duration::from_secs(1609459200);
        assert_eq!(time, expected);
    }

    /// Plan 225 — adversarial input cases that pre-fix would have
    /// panicked in release mode via `UNIX_EPOCH + Duration`. The
    /// function's contract is `None` on malformed input; every
    /// row below must return None without panic.
    mod parse_timespec_adversarial {
        use super::*;

        fn bytes(secs: i64, nsecs: i64) -> [u8; 16] {
            let mut out = [0u8; 16];
            out[..8].copy_from_slice(&secs.to_ne_bytes());
            out[8..].copy_from_slice(&nsecs.to_ne_bytes());
            out
        }

        #[test]
        fn returns_none_on_too_short_input() {
            assert!(parse_timespec(&[0u8; 15]).is_none());
            assert!(parse_timespec(&[]).is_none());
        }

        #[test]
        fn returns_none_on_zero_zero_no_handshake_sentinel() {
            assert!(parse_timespec(&bytes(0, 0)).is_none());
        }

        #[test]
        fn returns_none_on_negative_secs() {
            // Pre-fix: `secs as u64` produces u64::MAX-ish, and
            // `UNIX_EPOCH + Duration::from_secs(huge)` panics.
            assert!(parse_timespec(&bytes(-1, 0)).is_none());
            assert!(parse_timespec(&bytes(i64::MIN, 0)).is_none());
            assert!(parse_timespec(&bytes(-1, 500_000_000)).is_none());
        }

        #[test]
        fn returns_none_on_negative_nsecs() {
            assert!(parse_timespec(&bytes(0, -1)).is_none());
            assert!(parse_timespec(&bytes(100, -1)).is_none());
            assert!(parse_timespec(&bytes(100, i64::MIN)).is_none());
        }

        #[test]
        fn returns_none_on_out_of_range_nsecs() {
            // Anything >= 1_000_000_000 is kernel-garbage. Pre-fix,
            // Duration::new normalized via carry which could
            // overflow secs.
            assert!(parse_timespec(&bytes(0, 1_000_000_000)).is_none());
            assert!(parse_timespec(&bytes(0, 1_500_000_000)).is_none());
            assert!(parse_timespec(&bytes(0, i64::MAX)).is_none());
        }

        #[test]
        fn handles_far_future_without_panic() {
            // i64::MAX seconds is the maximum a valid kernel
            // timespec can carry. Pre-fix this would either parse
            // with a wildly-out-of-range u64 cast or panic on the
            // subsequent `UNIX_EPOCH + duration`. Post-fix we use
            // `checked_add` so the function returns either Some
            // (if the platform's `SystemTime` representation can
            // hold that many post-epoch seconds, which Linux's
            // Duration-backed impl can) or None (if it can't) —
            // either is a valid contract; the must-not-panic
            // property is what we lock here.
            let _ = parse_timespec(&bytes(i64::MAX, 0));
            // And the saturating case where nsecs is at the
            // boundary of allowed range.
            let _ = parse_timespec(&bytes(i64::MAX, 999_999_999));
        }

        #[test]
        fn returns_some_on_a_real_handshake_timestamp() {
            // 2024-01-01 00:00:00 UTC — well within range.
            let secs = 1_704_067_200_i64;
            let nsecs = 123_456_789_i64;
            let st = parse_timespec(&bytes(secs, nsecs))
                .expect("real timestamp must parse");
            let d = st.duration_since(UNIX_EPOCH).unwrap();
            assert_eq!(d.as_secs(), secs as u64);
            assert_eq!(d.subsec_nanos(), nsecs as u32);
        }
    }

    // ====================================================================
    // #277 — dump continuations coalesce by public key
    // ====================================================================

    fn key(b: u8) -> [u8; WG_KEY_LEN] {
        [b; WG_KEY_LEN]
    }

    #[test]
    fn a_continuation_appends_allowed_ips_and_keeps_the_stats() {
        // What the kernel actually sends when a peer's allowed_ips
        // straddle an skb boundary: chunk 1 has the scalars and some
        // IPs, chunk 2 repeats only the public key and the rest.
        let mut first = WgPeer {
            public_key: key(1),
            rx_bytes: 4096,
            tx_bytes: 8192,
            endpoint: Some("10.0.0.1:51820".parse().unwrap()),
            persistent_keepalive: Some(25),
            allowed_ips: vec![AllowedIp::v4("10.1.0.0".parse().unwrap(), 16)],
            ..WgPeer::default()
        };
        let continuation = WgPeer {
            public_key: key(1),
            allowed_ips: vec![AllowedIp::v4("10.2.0.0".parse().unwrap(), 16)],
            ..WgPeer::default()
        };

        first.merge_continuation(continuation);

        assert_eq!(first.allowed_ips.len(), 2, "allowed IPs must accumulate");
        // The continuation's zeros are "not repeated", not "zero".
        assert_eq!(first.rx_bytes, 4096);
        assert_eq!(first.tx_bytes, 8192);
        assert!(first.endpoint.is_some(), "endpoint must survive the merge");
        assert_eq!(first.persistent_keepalive, Some(25));
    }

    #[test]
    fn a_continuation_that_does_carry_values_wins() {
        let mut first = WgPeer {
            public_key: key(2),
            ..WgPeer::default()
        };
        first.merge_continuation(WgPeer {
            public_key: key(2),
            rx_bytes: 7,
            endpoint: Some("192.0.2.1:1".parse().unwrap()),
            ..WgPeer::default()
        });
        assert_eq!(first.rx_bytes, 7);
        assert!(first.endpoint.is_some());
    }
}
