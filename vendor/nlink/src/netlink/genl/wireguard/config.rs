//! Declarative WireGuard configuration (Plan 196).
//!
//! Mirrors [`crate::netlink::config::NetworkConfig`] and
//! [`crate::netlink::nftables::config::NftablesConfig`] for
//! the WireGuard GENL family: describe the desired device +
//! peer state, then `.diff()` / `.apply()` against the
//! running kernel.
//!
//! # Why this exists
//!
//! The imperative [`Connection::<Wireguard>::set_device`] +
//! [`set_peer`] / [`del_peer`] surface ships full
//! coverage, but consumers wanting "this is my desired state
//! — reconcile" semantics had to hand-roll the diff. This
//! module ships the typed shape so the work is one apply,
//! not N add/modify/remove calls.
//!
//! [`Connection::<Wireguard>::set_device`]: crate::Connection
//! [`set_peer`]: crate::Connection
//! [`del_peer`]: crate::Connection
//!
//! # Key writes and readback
//!
//! [`WireguardConfig::diff`] compares a declared `private_key` with the
//! kernel's, X25519-clamped as the kernel stores it (#410), and a
//! peer's `preshared_key` with the one `GET_DEVICE` returns (#411), so a
//! re-apply with nothing changed writes nothing. Both reads need
//! `CAP_NET_ADMIN`, as below.
//!
//! For callers that read device state directly: `WG_CMD_GET_DEVICE`
//! is gated behind `CAP_NET_ADMIN` in the device's netns at the
//! command level (`uns-admin-perm` in the kernel's netlink spec).
//! Privileged callers get the device including `WGDEVICE_A_PRIVATE_KEY`
//! (as `wg showconf` does); unprivileged callers hit the gate and
//! see `Error::from(crate::netlink::ErrorDetail::Kernel { errno: EPERM })` on the whole call — there's
//! no partial-reply path where `WgDevice::private_key` comes back as
//! `None` due to insufficient privilege. [`WgDevice::private_key`]
//! is `None` only when the device has no key configured (i.e. before
//! any `set_device(... .private_key(...))`). A peer's `preshared_key`
//! comes back the same way, `None` when the peer has none.
//!
//! [`WgDevice::private_key`]: super::types::WgDevice::private_key

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use super::types::{AllowedIp, WG_KEY_LEN, WgDevice, WgPeer, WgPeerBuilder};
use crate::{Connection, Error, Result, netlink::protocol::Wireguard};

// =============================================================================
// PublicKey newtype (Plan 196 §2.3b)
// =============================================================================

/// A WireGuard public key — a 32-byte Curve25519 point.
///
/// Round-trips with the canonical base64 representation
/// (44 chars, `=`-padded) via [`FromStr`] and [`fmt::Display`],
/// matching what `wg pubkey` / `wg show` emit.
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::genl::wireguard::PublicKey;
/// let pk: PublicKey = "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0WI=".parse()?;
/// assert_eq!(pk.to_string(), "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0WI=");
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; WG_KEY_LEN]);

impl PublicKey {
    /// Wrap a raw 32-byte buffer as a key. No validation —
    /// the kernel rejects invalid points on `SET_DEVICE`.
    pub fn from_bytes(bytes: [u8; WG_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; WG_KEY_LEN] {
        &self.0
    }
}

impl From<[u8; WG_KEY_LEN]> for PublicKey {
    fn from(bytes: [u8; WG_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl From<PublicKey> for [u8; WG_KEY_LEN] {
    fn from(pk: PublicKey) -> Self {
        pk.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&b64_encode_32(&self.0))
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        b64_decode_32(s)
            .map(Self)
            .ok_or_else(|| Error::invalid_message(format!("invalid WireGuard public key: {s:?}")))
    }
}

/// A WireGuard private key: 32 bytes, X25519-clamped as the kernel stores
/// it.
///
/// Round-trips with the base64 `wg genkey` prints, via [`FromStr`] and
/// [`fmt::Display`] — `Display` writes the secret, so print it only where
/// a key belongs. [`fmt::Debug`] never shows it (#499). Pass it where a
/// raw key is taken with `.into()`. With the `wireguard-keys` feature,
/// [`generate`](Self::generate) and [`public_key`](Self::public_key) do
/// what `wg genkey` and `wg pubkey` do (#529).
///
/// ```
/// use nlink::netlink::genl::wireguard::PrivateKey;
/// // RFC 7748 §6.1, Alice's private key.
/// let key: PrivateKey = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=".parse().unwrap();
/// assert_eq!(key.to_string(), "cAdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LGo=");
/// assert!(!format!("{key:?}").contains("cAdt"));
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey([u8; WG_KEY_LEN]);

impl PrivateKey {
    /// Wrap 32 bytes as a key, clamped (`curve25519_clamp_secret`) as the
    /// kernel would store them.
    pub fn from_bytes(bytes: [u8; WG_KEY_LEN]) -> Self {
        Self(clamp_private_key(bytes))
    }

    /// The key's 32 bytes, clamped.
    pub fn as_bytes(&self) -> &[u8; WG_KEY_LEN] {
        &self.0
    }

    /// A new random key, as `wg genkey` makes: 32 bytes from the kernel's
    /// random source (`getrandom(2)`), clamped.
    #[cfg(feature = "wireguard-keys")]
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; WG_KEY_LEN];
        let mut filled = 0;
        while filled < bytes.len() {
            // SAFETY: the pointer and length name the unfilled tail of
            // `bytes`, which outlives the call.
            let n = unsafe {
                libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }
            filled += n as usize;
        }
        Ok(Self::from_bytes(bytes))
    }

    /// The public key of this private key, as `wg pubkey` derives it
    /// (X25519 with the base point).
    #[cfg(feature = "wireguard-keys")]
    pub fn public_key(&self) -> PublicKey {
        let secret = x25519_dalek::StaticSecret::from(self.0);
        PublicKey(x25519_dalek::PublicKey::from(&secret).to_bytes())
    }
}

impl From<[u8; WG_KEY_LEN]> for PrivateKey {
    fn from(bytes: [u8; WG_KEY_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<PrivateKey> for [u8; WG_KEY_LEN] {
    fn from(key: PrivateKey) -> Self {
        key.0
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PrivateKey")
            .field(&crate::util::SecretBytes(&self.0))
            .finish()
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&b64_encode_32(&self.0))
    }
}

impl FromStr for PrivateKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        // The input is not echoed: it is a secret.
        b64_decode_32(s)
            .map(Self::from_bytes)
            .ok_or_else(|| Error::invalid_message("invalid WireGuard private key"))
    }
}

/// Encode a 32-byte buffer as 44 base64 chars (RFC 4648,
/// alphabet `A-Za-z0-9+/`, single `=` pad).
fn b64_encode_32(bytes: &[u8; WG_KEY_LEN]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(44);
    // 32 bytes = 10 full triplets (30 bytes) + 2 trailing
    for chunk in bytes.chunks(3) {
        match chunk.len() {
            3 => {
                let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
                out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
                out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
                out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
                out.push(ALPHA[(n & 0x3f) as usize] as char);
            }
            2 => {
                let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8);
                out.push(ALPHA[((n >> 18) & 0x3f) as usize] as char);
                out.push(ALPHA[((n >> 12) & 0x3f) as usize] as char);
                out.push(ALPHA[((n >> 6) & 0x3f) as usize] as char);
                out.push('=');
            }
            _ => unreachable!("32 % 3 = 2"),
        }
    }
    out
}

/// Decode 43 (unpadded) or 44 (padded) base64 chars (RFC 4648) into
/// a 32-byte buffer. Returns `None` for any malformed input.
///
/// Plan 215 (0.19) — pre-fix this required exactly 44 chars with the
/// trailing `=`. WireGuard's `wg pubkey` tool emits padded form, so
/// `wg`-tool round-trips worked, but some YAML/JSON serializers strip
/// base64 padding (it's technically optional per RFC 4648 §3.2), and
/// nlink-side decoding of those config files failed silently. Now
/// accepts both forms.
fn b64_decode_32(s: &str) -> Option<[u8; WG_KEY_LEN]> {
    // Accept both padded (44 chars ending in `=`) and unpadded (43
    // chars) base64. Strip the optional trailing `=`.
    let trimmed = s.trim_end_matches('=');
    if trimmed.len() != 43 {
        return None;
    }
    let mut out = [0u8; WG_KEY_LEN];
    let mut buf = 0u32;
    let mut bits = 0u32;
    let mut written = 0usize;
    for ch in trimmed.chars() {
        let v = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            'a'..='z' => ch as u32 - 'a' as u32 + 26,
            '0'..='9' => ch as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[written] = ((buf >> bits) & 0xff) as u8;
            written += 1;
            if written == 32 {
                break;
            }
        }
    }
    (written == 32).then_some(out)
}

/// Desired WireGuard configuration — one or more devices,
/// each with their peers. Plan 196.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use = "WireguardConfig does nothing unless .diff() or .apply() is called"]
pub struct WireguardConfig {
    devices: Vec<DeclaredWgDevice>,
}

#[nlink_macros::send_futures]
impl WireguardConfig {
    /// Build an empty configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a WireGuard device (interface) and its peers
    /// via a builder closure.
    ///
    /// ```no_run
    /// # use nlink::netlink::genl::wireguard::AllowedIp;
    /// # use nlink::netlink::genl::wireguard::WireguardConfig;
    /// # use std::net::Ipv4Addr;
    /// # use std::time::Duration;
    /// let cfg = WireguardConfig::new()
    ///     .device("wg0", |d| {
    ///         d.private_key([0xaa; 32])
    ///             .listen_port(51820)
    ///             .peer([0xbb; 32], |p| {
    ///                 p.endpoint("203.0.113.1:51820".parse().unwrap())
    ///                  .persistent_keepalive(Duration::from_secs(25))
    ///                  .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
    ///             })
    ///     });
    /// ```
    pub fn device(
        mut self,
        ifname: impl Into<String>,
        f: impl FnOnce(DeclaredWgDeviceBuilder) -> DeclaredWgDeviceBuilder,
    ) -> Self {
        let builder = f(DeclaredWgDeviceBuilder::new(ifname.into()));
        self.devices.push(builder.build());
        self
    }

    /// View the declared devices (read-only).
    pub fn devices(&self) -> &[DeclaredWgDevice] {
        &self.devices
    }

    /// `true` when the config declares no device (#531).
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Compute the diff between desired (this config) and
    /// current kernel state. Plan 196.
    ///
    /// A declared device that doesn't exist in the kernel (or isn't
    /// a WireGuard link) is reported in
    /// [`WireguardConfigDiff::devices_to_add`] rather than failing
    /// the whole diff (#169). Create the missing links with
    /// [`ensure_devices`](Self::ensure_devices) (or declare them in
    /// a `NetworkConfig` / [`Stack`](crate::facade::Stack)), then
    /// diff again — the fresh device's configuration lands in
    /// `devices_to_modify`.
    pub async fn diff(&self, conn: &Connection<Wireguard>) -> Result<WireguardConfigDiff> {
        self.validate()?;
        let mut diff = WireguardConfigDiff::default();

        for declared in &self.devices {
            let current = match conn.get_device_by_name(&declared.ifname).await {
                Ok(current) => current,
                // Absent link (or not a WG link → GENL says no such
                // device). Bootstrap path: report, don't fail.
                Err(e) if e.is_not_found() || e.is_no_device() => {
                    diff.devices_to_add.push(declared.ifname.clone());
                    continue;
                }
                Err(e) => return Err(e),
            };

            let device_changes = declared.diff_against(&current);
            if !device_changes.is_empty() {
                diff.devices_to_modify
                    .push((declared.ifname.clone(), device_changes));
            }
        }
        diff.source = Some(std::sync::Arc::new(self.clone()));

        Ok(diff)
    }

    /// Refuse an allowed-IP prefix declared on two peers of one device
    /// (#498), and a device declared twice.
    ///
    /// The kernel keeps a device's allowed IPs in one trie, so a prefix
    /// belongs to at most one peer: writing it on peer B takes it from
    /// peer A, silently. Declared on both, every apply rewrote every peer
    /// that "lost" it and the diff never emptied — a hub declaring each
    /// spoke with the tunnel's /24 is the usual way in. Compared as the
    /// kernel stores them, masked to their prefix. [`diff`](Self::diff)
    /// runs this first.
    pub fn validate(&self) -> Result<()> {
        use crate::netlink::error::ValidationErrorInfo;
        let mut errors = Vec::new();
        let mut names = std::collections::HashSet::new();
        for device in &self.devices {
            // Two declarations of one device are diffed separately and
            // undo each other.
            if !names.insert(device.ifname.as_str()) {
                errors.push(ValidationErrorInfo::new(
                    format!("devices.{}", device.ifname),
                    "declared more than once",
                ));
            }
            let mut owner: std::collections::HashMap<(IpAddr, u8), &[u8; WG_KEY_LEN]> =
                std::collections::HashMap::new();
            for peer in &device.peers {
                if peer
                    .persistent_keepalive
                    .is_some_and(|ka| ka > Duration::from_secs(u64::from(u16::MAX)))
                {
                    errors.push(ValidationErrorInfo::new(
                        format!("devices.{}.peers", device.ifname),
                        format!(
                            "peer {}: a persistent keepalive longer than 65535 s, the most \
                             WireGuard takes",
                            b64_encode_32(&peer.public_key)
                        ),
                    ));
                }
                for prefix in allowed_ip_set(&peer.allowed_ips) {
                    match owner.get(&prefix) {
                        Some(first) if *first != &peer.public_key => {
                            errors.push(ValidationErrorInfo::new(
                                format!("devices.{}.peers", device.ifname),
                                format!(
                                    "{}/{} is an allowed IP of two peers, {} and {}; \
                                     the kernel gives a prefix to one peer only",
                                    prefix.0,
                                    prefix.1,
                                    b64_encode_32(first),
                                    b64_encode_32(&peer.public_key),
                                ),
                            ));
                        }
                        Some(_) => {}
                        None => {
                            owner.insert(prefix, &peer.public_key);
                        }
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(crate::netlink::Error::validation(errors))
        }
    }

    /// Create any declared WireGuard links that don't exist yet and
    /// bring every declared link **up** (bootstrap for
    /// [`diff`](Self::diff)'s `devices_to_add`).
    ///
    /// Link creation is an rtnetlink operation, so this takes a
    /// `Connection<Route>` — pass one bound to the **same network
    /// namespace** as the WireGuard connection you'll `apply` with.
    /// Returns the names of the links it created. Idempotent:
    /// already-existing links are skipped, and a link that is already
    /// up stays up.
    ///
    /// The documented sequence is `ensure_devices` → `NetworkConfig::apply`
    /// (tunnel addresses, routes via the peer's tunnel address) →
    /// [`apply`](Self::apply). `add_link` creates a link administratively
    /// down, and the kernel refuses a route whose nexthop device is down
    /// (`ENETDOWN`, "Device for nexthop is not up") — so until 0.27 that
    /// sequence failed at step two for every route via the tunnel, and
    /// every caller had to add its own `set_link_up` loop (#329). A
    /// WireGuard link is useless down; this is desired state, so **all**
    /// declared devices are brought up on every call, not just the ones
    /// this call created.
    pub async fn ensure_devices(
        &self,
        route: &Connection<crate::netlink::Route>,
    ) -> Result<Vec<String>> {
        let mut created = Vec::new();
        for declared in &self.devices {
            match route
                .add_link(crate::netlink::link::WireguardLink::new(&declared.ifname))
                .await
            {
                Ok(()) => created.push(declared.ifname.clone()),
                Err(e) if e.is_already_exists() => {}
                Err(e) => return Err(e),
            }
            route.set_link_up(declared.ifname.as_str()).await?;
        }
        Ok(created)
    }

    /// Apply, retrying what a concurrent change can cause (`EBUSY`,
    /// `EAGAIN`, an interrupted dump), each attempt diffing again. With
    /// `opts.dry_run`, only the diff: the report's `changes_made` is its
    /// change count. Mirrors
    /// [`NftablesConfig::apply_reconcile`](crate::netlink::nftables::config::NftablesConfig::apply_reconcile)
    /// and
    /// [`NetworkConfig::apply_reconcile`](crate::netlink::config::NetworkConfig::apply_reconcile).
    pub async fn apply_reconcile(
        &self,
        conn: &Connection<Wireguard>,
        opts: crate::netlink::reconcile::ReconcileOptions,
    ) -> Result<crate::netlink::reconcile::ReconcileReport> {
        use crate::netlink::reconcile::ReconcileReport;
        if opts.dry_run {
            let diff = self.diff(conn).await?;
            return Ok(ReconcileReport {
                attempts: 1,
                changes_made: diff.change_count(),
                dry_run: true,
                ..ReconcileReport::default()
            });
        }
        let (result, attempts) = opts
            .retry(crate::netlink::reconcile::transient, || self.apply(conn))
            .await?;
        Ok(ReconcileReport {
            attempts,
            changes_made: result.total_writes(),
            ..ReconcileReport::default()
        })
    }

    /// Apply this configuration: compute the diff, then
    /// dispatch the kernel mutations. Plan 196.
    ///
    /// Fails with a descriptive error if a declared device doesn't
    /// exist — WG_CMD_SET_DEVICE can't create links. Create missing
    /// links first via [`ensure_devices`](Self::ensure_devices) (or
    /// declare them in a `NetworkConfig` /
    /// [`Stack`](crate::facade::Stack), which orders the layers).
    pub async fn apply(&self, conn: &Connection<Wireguard>) -> Result<WireguardApplyResult> {
        self.diff(conn).await?.apply_declared(conn, self).await
    }

    /// Build a typical single-peer **client** configuration: one
    /// interface with a private key, and one peer (the server) with an
    /// endpoint, allowed-IPs, and an optional persistent-keepalive.
    ///
    /// This is the common "import a server-provided profile" shape. For
    /// anything richer (multiple peers, fwmark, listen-port) use the
    /// [`device`](Self::device) builder or [`from_wg_quick`](Self::from_wg_quick).
    ///
    /// ```no_run
    /// # use nlink::netlink::genl::wireguard::AllowedIp;
    /// # use nlink::netlink::genl::wireguard::WireguardConfig;
    /// # use std::net::Ipv4Addr;
    /// # use std::time::Duration;
    /// # let my_private_key = [0u8; 32];
    /// # let server_public_key = [0u8; 32];
    /// let cfg = WireguardConfig::client(
    ///     "wg0",
    ///     my_private_key,                       // [u8; 32]
    ///     server_public_key,                    // [u8; 32]
    ///     "203.0.113.1:51820".parse().unwrap(), // SocketAddr
    ///     vec![AllowedIp::v4(Ipv4Addr::UNSPECIFIED, 0)],
    ///     Some(Duration::from_secs(25)),
    /// );
    /// ```
    pub fn client(
        ifname: impl Into<String>,
        private_key: [u8; WG_KEY_LEN],
        server_public_key: [u8; WG_KEY_LEN],
        endpoint: SocketAddr,
        allowed_ips: Vec<AllowedIp>,
        persistent_keepalive: Option<Duration>,
    ) -> Self {
        let peer = DeclaredWgPeer {
            public_key: server_public_key,
            preshared_key: None,
            endpoint: Some(endpoint),
            persistent_keepalive,
            allowed_ips,
            endpoint_policy: EndpointPolicy::default(),
        };
        let device = DeclaredWgDevice {
            ifname: ifname.into(),
            private_key: Some(private_key),
            listen_port: None,
            fwmark: None,
            peers: vec![peer],
        };
        let mut cfg = WireguardConfig::new();
        cfg.push_device(device);
        cfg
    }

    /// Parse a `wg-quick` / `wg setconf` style `[Interface]` + `[Peer]`
    /// configuration into a single-device `WireguardConfig`.
    ///
    /// The interface name is supplied separately (`wg-quick` derives it
    /// from the file name, which isn't part of the file body).
    ///
    /// Recognised keys:
    /// - `[Interface]`: `PrivateKey`, `ListenPort`, `FwMark` (the
    ///   kernel-level device attributes). The `wg-quick`-only keys
    ///   (`Address`, `DNS`, `MTU`, `Table`, `PreUp`/`PostUp`/`PreDown`/
    ///   `PostDown`, `SaveConfig`) are accepted and ignored — they're
    ///   handled by `wg-quick`'s userspace wrapper, not the kernel
    ///   device.
    /// - `[Peer]`: `PublicKey`, `PresharedKey`, `Endpoint` (must be
    ///   `IP:port` — hostnames are rejected, no DNS resolution),
    ///   `AllowedIPs` (comma-separated CIDRs), `PersistentKeepalive`
    ///   (seconds, or `off`).
    ///
    /// Keys are matched case-insensitively. Genuinely unknown keys are
    /// an error (not silently dropped).
    pub fn from_wg_quick(ifname: impl Into<String>, contents: &str) -> Result<Self> {
        parse_wg_quick(ifname.into(), contents)
    }

    /// View the declared devices, mutable — used by the wg-quick parser
    /// helper. (internal)
    fn push_device(&mut self, device: DeclaredWgDevice) {
        self.devices.push(device);
    }
}

/// Parse a CIDR string (`10.0.0.0/24`, `0.0.0.0/0`, `::/0`, or a bare
/// address) into an [`AllowedIp`]. A bare address defaults to /32 (v4)
/// or /128 (v6).
fn parse_cidr(s: &str) -> Result<AllowedIp> {
    let s = s.trim();
    let (addr_str, cidr_str) = match s.split_once('/') {
        Some((a, c)) => (a, Some(c)),
        None => (s, None),
    };
    let addr: IpAddr = addr_str
        .parse()
        .map_err(|_| Error::invalid_message(format!("wireguard config: invalid IP `{addr_str}`")))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let cidr = match cidr_str {
        Some(c) => c.parse::<u8>().map_err(|_| {
            Error::invalid_message(format!("wireguard config: invalid prefix `{c}`"))
        })?,
        None => max,
    };
    if cidr > max {
        return Err(Error::invalid_message(format!(
            "wireguard config: prefix /{cidr} out of range for {} (max /{max})",
            if addr.is_ipv4() { "IPv4" } else { "IPv6" }
        )));
    }
    Ok(match addr {
        IpAddr::V4(a) => AllowedIp::v4(a, cidr),
        IpAddr::V6(a) => AllowedIp::v6(a, cidr),
    })
}

/// Decode a base64 WireGuard key, mapping failure to a clear error.
fn parse_key(field: &str, value: &str) -> Result<[u8; WG_KEY_LEN]> {
    b64_decode_32(value)
        .ok_or_else(|| Error::invalid_message(format!("wireguard config: invalid {field} key")))
}

/// `wg-quick`/`wg setconf` INI parser. Builds a single device named
/// `ifname` plus its peers.
fn parse_wg_quick(ifname: String, contents: &str) -> Result<WireguardConfig> {
    /// Which section the cursor is in.
    enum Section {
        None,
        Interface,
        Peer,
    }

    let mut section = Section::None;
    let mut device = DeclaredWgDevice {
        ifname,
        private_key: None,
        listen_port: None,
        fwmark: None,
        peers: Vec::new(),
    };
    let mut current_peer: Option<DeclaredWgPeer> = None;

    // `[Interface]` keys that wg-quick consumes in userspace and the
    // kernel device doesn't model — accept and ignore.
    const IGNORED_INTERFACE_KEYS: &[&str] = &[
        "address",
        "dns",
        "mtu",
        "table",
        "preup",
        "postup",
        "predown",
        "postdown",
        "saveconfig",
    ];

    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        // Section header.
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            match name.trim().to_ascii_lowercase().as_str() {
                "interface" => section = Section::Interface,
                "peer" => {
                    if let Some(p) = current_peer.take() {
                        device.peers.push(p);
                    }
                    section = Section::Peer;
                    current_peer = Some(DeclaredWgPeer {
                        public_key: [0u8; WG_KEY_LEN],
                        preshared_key: None,
                        endpoint: None,
                        persistent_keepalive: None,
                        allowed_ips: Vec::new(),
                        endpoint_policy: EndpointPolicy::default(),
                    });
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "wireguard config: unknown section `[{other}]` at line {}",
                        lineno + 1
                    )));
                }
            }
            continue;
        }

        let (key, value) = line.split_once('=').ok_or_else(|| {
            Error::invalid_message(format!(
                "wireguard config: expected `key = value` at line {}: `{line}`",
                lineno + 1
            ))
        })?;
        let key_lc = key.trim().to_ascii_lowercase();
        let value = value.trim();

        match section {
            Section::None => {
                return Err(Error::invalid_message(format!(
                    "wireguard config: key `{}` before any [Interface]/[Peer] section (line {})",
                    key.trim(),
                    lineno + 1
                )));
            }
            Section::Interface => match key_lc.as_str() {
                "privatekey" => device.private_key = Some(parse_key("PrivateKey", value)?),
                "listenport" => {
                    device.listen_port = Some(value.parse::<u16>().map_err(|_| {
                        Error::invalid_message(format!(
                            "wireguard config: invalid ListenPort `{value}`"
                        ))
                    })?);
                }
                "fwmark" => device.fwmark = Some(parse_fwmark(value)?),
                k if IGNORED_INTERFACE_KEYS.contains(&k) => { /* wg-quick userspace key */ }
                _ => {
                    return Err(Error::invalid_message(format!(
                        "wireguard config: unknown [Interface] key `{}` (line {})",
                        key.trim(),
                        lineno + 1
                    )));
                }
            },
            Section::Peer => {
                let peer = current_peer
                    .as_mut()
                    .expect("peer section sets current_peer");
                match key_lc.as_str() {
                    "publickey" => peer.public_key = parse_key("PublicKey", value)?,
                    "presharedkey" => peer.preshared_key = Some(parse_key("PresharedKey", value)?),
                    "endpoint" => {
                        peer.endpoint = Some(value.parse::<SocketAddr>().map_err(|_| {
                            Error::invalid_message(format!(
                                "wireguard config: Endpoint `{value}` must be IP:port \
                                 (hostnames are not resolved)"
                            ))
                        })?);
                    }
                    "allowedips" => {
                        for part in value.split(',') {
                            let part = part.trim();
                            if part.is_empty() {
                                continue;
                            }
                            peer.allowed_ips.push(parse_cidr(part)?);
                        }
                    }
                    "persistentkeepalive" => {
                        if !value.eq_ignore_ascii_case("off") {
                            let secs = value.parse::<u16>().map_err(|_| {
                                Error::invalid_message(format!(
                                    "wireguard config: invalid PersistentKeepalive `{value}`"
                                ))
                            })?;
                            if secs != 0 {
                                peer.persistent_keepalive = Some(Duration::from_secs(secs as u64));
                            }
                        }
                    }
                    _ => {
                        return Err(Error::invalid_message(format!(
                            "wireguard config: unknown [Peer] key `{}` (line {})",
                            key.trim(),
                            lineno + 1
                        )));
                    }
                }
            }
        }
    }

    if let Some(p) = current_peer.take() {
        device.peers.push(p);
    }

    // A peer with no PublicKey set is malformed.
    for (i, p) in device.peers.iter().enumerate() {
        if p.public_key == [0u8; WG_KEY_LEN] {
            return Err(Error::invalid_message(format!(
                "wireguard config: [Peer] #{} is missing PublicKey",
                i + 1
            )));
        }
    }

    let mut cfg = WireguardConfig::new();
    cfg.push_device(device);
    Ok(cfg)
}

/// Parse an `FwMark` value: decimal, `0x`-hex, or `off` (= 0).
fn parse_fwmark(s: &str) -> Result<u32> {
    if s.eq_ignore_ascii_case("off") {
        return Ok(0);
    }
    let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => s.parse::<u32>(),
    };
    parsed.map_err(|_| Error::invalid_message(format!("wireguard config: invalid FwMark `{s}`")))
}

/// Allowed IPs as the kernel's trie holds them: each masked to its prefix
/// length, each prefix once, in a canonical order.
/// A host prefix the peer holds neither as declared nor as removed: one
/// it does not hold, for the removal probe.
fn absent_prefix(declared: &[AllowedIp], removed: &[AllowedIp]) -> AllowedIp {
    let held = |ip: &AllowedIp| declared.iter().chain(removed).any(|h| h.addr == ip.addr && h.cidr == ip.cidr);
    (0..=u8::MAX)
        .map(|i| AllowedIp::v4(std::net::Ipv4Addr::new(255, 255, 255, 255 - i), 32))
        .find(|ip| !held(ip))
        .unwrap_or(AllowedIp::v4(std::net::Ipv4Addr::BROADCAST, 32))
}

fn allowed_ip_set(ips: &[AllowedIp]) -> std::collections::BTreeSet<(IpAddr, u8)> {
    ips.iter()
        .map(|ip| {
            let addr = match ip.addr {
                IpAddr::V4(v4) => {
                    let mask = u32::MAX
                        .checked_shl(32 - u32::from(ip.cidr.min(32)))
                        .unwrap_or(0);
                    IpAddr::V4(std::net::Ipv4Addr::from(u32::from(v4) & mask))
                }
                IpAddr::V6(v6) => {
                    let mask = u128::MAX
                        .checked_shl(128 - u32::from(ip.cidr.min(128)))
                        .unwrap_or(0);
                    IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & mask))
                }
            };
            (addr, ip.cidr)
        })
        .collect()
}

/// A private key as the kernel keeps it: X25519-clamped.
///
/// `wg_noise_set_static_identity_private_key()` copies the key and runs
/// `curve25519_clamp_secret()` on it — clear the low three bits and the
/// top bit, set bit 254 — and `GET_DEVICE` returns that copy. A key from
/// `wg genkey` is already clamped; any other 32 bytes are not.
/// A persistent-keepalive interval in the whole seconds WireGuard counts,
/// rounded **up**: truncated, 500 ms was 0, which turns keepalive off
/// (#529). `Duration::ZERO` is 0, off. Past `u16::MAX` seconds it
/// saturates; [`WireguardConfig::validate`] refuses that.
fn keepalive_secs(interval: Duration) -> u16 {
    let secs = interval.as_secs() + u64::from(interval.subsec_nanos() > 0);
    u16::try_from(secs).unwrap_or(u16::MAX)
}

fn clamp_private_key(mut key: [u8; WG_KEY_LEN]) -> [u8; WG_KEY_LEN] {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

// =============================================================================
// Declared types
// =============================================================================

/// A declared WireGuard device. Plan 196.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeclaredWgDevice {
    pub ifname: String,
    pub private_key: Option<[u8; WG_KEY_LEN]>,
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub peers: Vec<DeclaredWgPeer>,
}

impl std::fmt::Debug for DeclaredWgDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("DeclaredWgDevice")
            .field("ifname", &self.ifname)
            .field(
                "private_key",
                &self
                    .private_key
                    .as_ref()
                    .map(|k| crate::util::SecretBytes(k.as_ref())),
            )
            .field("listen_port", &self.listen_port)
            .field("fwmark", &self.fwmark)
            .field("peers", &self.peers)
            .finish()
    }
}

impl DeclaredWgDevice {
    fn diff_against(&self, current: &WgDevice) -> DeviceChanges {
        let mut changes = DeviceChanges::default();

        // private_key — compared, not assumed dirty.
        //
        // This used to mark it dirty whenever declared, on the stated
        // premise that the current value "can never be compared". The
        // premise does not hold: `parse_device_attr_scalar` reads
        // `WGDEVICE_A_PRIVATE_KEY`, the kernel returns it to a
        // `CAP_NET_ADMIN` `GET_DEVICE`, and `parse_key` already
        // normalises all-zeros to `None` so "unset" is distinguishable.
        //
        // The consequence was real: `diff` was **never empty** when a
        // private key was declared, so any supervisor loop treating
        // "diff non-empty" as drift rewrote the key on every tick, and
        // "the second apply is a no-op" could not be asserted (#281).
        //
        // If the kernel does withhold it — an unprivileged GET, say —
        // `current.private_key` is `None` and the key is written, which
        // is the old behaviour for exactly the case that justified it.
        //
        // Compared clamped: the kernel stores (and dumps) the key after
        // X25519 clamping, so an unclamped declared key — any 32 bytes
        // that did not come from `wg genkey` — never matched and was
        // rewritten on every apply (#410).
        if let Some(declared) = self.private_key
            && current.private_key != Some(clamp_private_key(declared))
        {
            changes.private_key_set = true;
        }
        // A declared port of 0 asks the kernel to pick one, and the port
        // it picked is then what `GET_DEVICE` reports — never 0. Compared
        // literally it never matched, and every apply wrote 0 again, which
        // `set_port()` takes as "bind a new random port": the device moved
        // port on every apply and its peers lost it (#414). Any port
        // satisfies a declared 0.
        if let Some(p) = self.listen_port
            && p != 0
            && current.listen_port != Some(p)
        {
            changes.listen_port_set = true;
        }
        if let Some(fw) = self.fwmark
            && current.fwmark != Some(fw)
        {
            changes.fwmark_set = true;
        }

        // Peers — symmetric diff by public_key.
        let curr_keys: std::collections::HashMap<&[u8; WG_KEY_LEN], &WgPeer> =
            current.peers.iter().map(|p| (&p.public_key, p)).collect();

        for declared in &self.peers {
            match curr_keys.get(&declared.public_key) {
                None => changes.peers_to_add.push(declared.clone()),
                Some(curr) => {
                    let pc = declared.diff_against(curr);
                    if !pc.is_empty() {
                        changes.peers_to_modify.push((declared.public_key, pc));
                    }
                }
            }
        }

        // Peers in kernel but not in declared config — removed.
        let declared_keys: std::collections::HashSet<&[u8; WG_KEY_LEN]> =
            self.peers.iter().map(|p| &p.public_key).collect();
        for curr_peer in &current.peers {
            if !declared_keys.contains(&curr_peer.public_key) {
                changes.peers_to_remove.push(curr_peer.public_key);
            }
        }

        changes
    }
}

/// Builder for [`DeclaredWgDevice`].
#[derive(Clone)]
#[must_use = "builders do nothing unless built"]
pub struct DeclaredWgDeviceBuilder {
    ifname: String,
    private_key: Option<[u8; WG_KEY_LEN]>,
    listen_port: Option<u16>,
    fwmark: Option<u32>,
    peers: Vec<DeclaredWgPeer>,
}

impl std::fmt::Debug for DeclaredWgDeviceBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("DeclaredWgDeviceBuilder")
            .field("ifname", &self.ifname)
            .field(
                "private_key",
                &self
                    .private_key
                    .as_ref()
                    .map(|k| crate::util::SecretBytes(k.as_ref())),
            )
            .field("listen_port", &self.listen_port)
            .field("fwmark", &self.fwmark)
            .field("peers", &self.peers)
            .finish()
    }
}

impl DeclaredWgDeviceBuilder {
    fn new(ifname: String) -> Self {
        Self {
            ifname,
            private_key: None,
            listen_port: None,
            fwmark: None,
            peers: Vec::new(),
        }
    }

    pub fn private_key(mut self, key: [u8; WG_KEY_LEN]) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Set the UDP listen port. 0 lets the kernel pick one, and is then
    /// satisfied by whatever port it picked (the diff does not rewrite
    /// it, which would rebind the device to another random port).
    pub fn listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    pub fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    pub fn peer(
        mut self,
        public_key: [u8; WG_KEY_LEN],
        f: impl FnOnce(DeclaredWgPeerBuilder) -> DeclaredWgPeerBuilder,
    ) -> Self {
        let builder = f(DeclaredWgPeerBuilder::new(public_key));
        self.peers.push(builder.build());
        self
    }

    fn build(self) -> DeclaredWgDevice {
        DeclaredWgDevice {
            ifname: self.ifname,
            private_key: self.private_key,
            listen_port: self.listen_port,
            fwmark: self.fwmark,
            peers: self.peers,
        }
    }
}

/// A declared WireGuard peer. Plan 196.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeclaredWgPeer {
    #[cfg_attr(feature = "serde", serde(serialize_with = "diff_serde::pubkey"))]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    pub public_key: [u8; WG_KEY_LEN],
    /// Serialized as a presence boolean (`preshared-key-set`) —
    /// secret material never leaves the process via serde.
    #[cfg_attr(
        feature = "serde",
        serde(
            rename = "preshared-key-set",
            serialize_with = "diff_serde::secret_presence"
        )
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "bool"))]
    pub preshared_key: Option<[u8; WG_KEY_LEN]>,
    pub endpoint: Option<SocketAddr>,
    /// Serialized as whole seconds (`persistent-keepalive-secs`).
    #[cfg_attr(
        feature = "serde",
        serde(
            rename = "persistent-keepalive-secs",
            serialize_with = "diff_serde::keepalive_secs"
        )
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<u16>"))]
    pub persistent_keepalive: Option<Duration>,
    pub allowed_ips: Vec<AllowedIp>,
    /// Whether the endpoint is kept to, or set once (#529).
    pub endpoint_policy: EndpointPolicy,
}

/// How a declared peer's endpoint is kept to (#529).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum EndpointPolicy {
    /// The endpoint is the declared one: a peer that roamed is put back.
    #[default]
    Enforce,
    /// The endpoint is set when the peer is added, and then left to the
    /// peer: one that roamed — its handshakes now come from elsewhere —
    /// keeps where it went.
    InitialOnly,
}

impl std::fmt::Debug for DeclaredWgPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("DeclaredWgPeer")
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
            .finish()
    }
}

impl DeclaredWgPeer {
    fn diff_against(&self, current: &WgPeer) -> PeerChanges {
        let mut changes = PeerChanges::default();

        // preshared_key — compared, not assumed dirty, for the reason
        // device.private_key is (#281): `get_peer()` puts
        // WGPEER_A_PRESHARED_KEY in every peer of a GET_DEVICE, which needs
        // CAP_NET_ADMIN anyway, and the parser maps the all-zero "no key"
        // to `None`. Marking it dirty whenever declared rewrote every
        // peer with a PSK on every apply (#411). A declared all-zero key
        // is the kernel's "none", so it compares as `None`.
        if let Some(psk) = self.preshared_key {
            let want = (psk != [0u8; WG_KEY_LEN]).then_some(psk);
            if current.preshared_key != want {
                changes.preshared_key_set = true;
            }
        }
        // A peer that may roam keeps the endpoint it moved to (#529).
        if let Some(ep) = self.endpoint
            && self.endpoint_policy == EndpointPolicy::Enforce
            && current.endpoint != Some(ep)
        {
            changes.endpoint_set = true;
        }
        if let Some(ka) = self.persistent_keepalive {
            let want_secs = keepalive_secs(ka);
            if current.persistent_keepalive != Some(want_secs) {
                changes.persistent_keepalive_set = true;
            }
        }
        // allowed_ips — compare as sets of what the kernel stores. The
        // kernel returns them in its own order, so sort; and its trie
        // keeps each prefix once, masked to its length
        // (`copy_and_assign_cidr()` in allowedips.c), so `10.0.0.5/24`
        // dumps as `10.0.0.0/24` and a prefix declared twice dumps once.
        // Comparing the declaration as written rewrote such a peer on
        // every apply (#TBD).
        let (want, have) = (allowed_ip_set(&self.allowed_ips), allowed_ip_set(&current.allowed_ips));
        if want != have {
            changes.allowed_ips_set = true;
            let as_ip = |&(addr, cidr): &(IpAddr, u8)| AllowedIp { addr, cidr };
            changes.allowed_ips_added = want.difference(&have).map(as_ip).collect();
            changes.allowed_ips_removed = have.difference(&want).map(as_ip).collect();
        }

        changes
    }

    fn apply_to_builder(&self, mut b: WgPeerBuilder) -> WgPeerBuilder {
        if let Some(psk) = self.preshared_key {
            b = b.preshared_key(psk);
        }
        if let Some(ep) = self.endpoint {
            b = b.endpoint(ep);
        }
        if let Some(ka) = self.persistent_keepalive {
            b = b.persistent_keepalive(keepalive_secs(ka));
        }
        for ip in &self.allowed_ips {
            b = b.allowed_ip(*ip);
        }
        // Always replace allowed_ips for an "in-config" peer
        // — the declarative model is "this is the full set",
        // not "merge". The kernel uses a flag (REPLACE_ALLOWEDIPS)
        // for this; WgPeerBuilder exposes it.
        b = b.replace_allowed_ips();
        b
    }

    fn apply_changes_to_builder(
        &self,
        mut b: WgPeerBuilder,
        changes: &PeerChanges,
        removal_supported: bool,
    ) -> WgPeerBuilder {
        if changes.preshared_key_set
            && let Some(psk) = self.preshared_key
        {
            b = b.preshared_key(psk);
        }
        if changes.endpoint_set
            && let Some(ep) = self.endpoint
        {
            b = b.endpoint(ep);
        }
        if changes.persistent_keepalive_set
            && let Some(ka) = self.persistent_keepalive
        {
            // Rounded as on the add path: truncating sent 0 for a
            // sub-second interval, which is "off" (#602).
            b = b.persistent_keepalive(keepalive_secs(ka));
        }
        if changes.allowed_ips_set {
            if changes.allowed_ips_removed.is_empty() || removal_supported {
                // Only what changed: replacing the whole list briefly
                // drops traffic to the prefixes that did not (#529).
                for ip in &changes.allowed_ips_added {
                    b = b.allowed_ip(*ip);
                }
                for ip in &changes.allowed_ips_removed {
                    b = b.remove_allowed_ip(*ip);
                }
            } else {
                for ip in &self.allowed_ips {
                    b = b.allowed_ip(*ip);
                }
                b = b.replace_allowed_ips();
            }
        }
        b
    }
}

/// Builder for [`DeclaredWgPeer`].
#[derive(Clone)]
#[must_use = "builders do nothing unless built"]
pub struct DeclaredWgPeerBuilder {
    public_key: [u8; WG_KEY_LEN],
    preshared_key: Option<[u8; WG_KEY_LEN]>,
    endpoint: Option<SocketAddr>,
    persistent_keepalive: Option<Duration>,
    allowed_ips: Vec<AllowedIp>,
    endpoint_policy: EndpointPolicy,
}

impl std::fmt::Debug for DeclaredWgPeerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material prints as its length, never its bytes (#499).
        f.debug_struct("DeclaredWgPeerBuilder")
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
            .finish()
    }
}

impl DeclaredWgPeerBuilder {
    fn new(public_key: [u8; WG_KEY_LEN]) -> Self {
        Self {
            public_key,
            preshared_key: None,
            endpoint: None,
            persistent_keepalive: None,
            allowed_ips: Vec::new(),
            endpoint_policy: EndpointPolicy::Enforce,
        }
    }

    /// Keep to the declared endpoint, or set it once and let the peer roam
    /// (#529): see [`EndpointPolicy`].
    pub fn endpoint_policy(mut self, policy: EndpointPolicy) -> Self {
        self.endpoint_policy = policy;
        self
    }

    pub fn preshared_key(mut self, key: [u8; WG_KEY_LEN]) -> Self {
        self.preshared_key = Some(key);
        self
    }

    pub fn endpoint(mut self, addr: SocketAddr) -> Self {
        self.endpoint = Some(addr);
        self
    }

    /// Send a keepalive this often. WireGuard counts whole seconds, so a
    /// fraction of one rounds up — 500 ms is 1 s; it was 0, which turns
    /// keepalive off (#529). `Duration::ZERO` turns it off. More than
    /// 65535 s fails [`WireguardConfig::validate`].
    pub fn persistent_keepalive(mut self, d: Duration) -> Self {
        self.persistent_keepalive = Some(d);
        self
    }

    pub fn allowed_ip(mut self, ip: AllowedIp) -> Self {
        self.allowed_ips.push(ip);
        self
    }

    fn build(self) -> DeclaredWgPeer {
        DeclaredWgPeer {
            public_key: self.public_key,
            preshared_key: self.preshared_key,
            endpoint: self.endpoint,
            persistent_keepalive: self.persistent_keepalive,
            allowed_ips: self.allowed_ips,
            endpoint_policy: self.endpoint_policy,
        }
    }
}

// =============================================================================
// Diff types
// =============================================================================

/// Plan 196 — diff between a [`WireguardConfig`] and the
/// current kernel state.
///
/// `#[non_exhaustive]` since 0.24 (#165): new change categories
/// (e.g. device bootstrap, #169) can appear without a major bump.
/// Construct via [`WireguardConfig::diff`], not literally.
///
/// With the `serde` feature the diff serializes to JSON for typed
/// drift reporting. **No key material is ever serialized**: public
/// keys render as base64, preshared/private keys as presence
/// booleans.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
#[must_use = "Diffs do nothing unless passed to `.apply()` or inspected"]
pub struct WireguardConfigDiff {
    /// Devices that need at least one mutation: device-
    /// level field change OR a peer add/modify/remove.
    pub devices_to_modify: Vec<(String, DeviceChanges)>,
    /// Declared devices that don't exist in the kernel (#169).
    /// Create them via [`WireguardConfig::ensure_devices`] (or a
    /// `NetworkConfig`/`Stack` declaring the links), then diff again.
    pub devices_to_add: Vec<String>,
    /// The config it was computed from, whose declared values an apply
    /// writes. Never serialized: it holds key material.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) source: Option<std::sync::Arc<WireguardConfig>>,
}

impl WireguardConfigDiff {
    /// The JSON Schema (draft 7) of the JSON a `WireguardConfigDiff` serializes to,
    /// pretty-printed. Requires the `schemars` feature. Publish it beside
    /// a `diff` output so a change to the diff's shape is a visible change
    /// to its schema (#531).
    #[cfg(feature = "schemars")]
    pub fn json_schema() -> String {
        crate::netlink::config::draft07_output_schema_text::<Self>()
    }

    /// [`json_schema`](Self::json_schema) as a [`schemars::Schema`].
    #[cfg(feature = "schemars")]
    pub fn json_schema_value() -> schemars::Schema {
        crate::netlink::config::draft07_output_schema::<Self>()
    }

    pub fn is_empty(&self) -> bool {
        self.devices_to_modify.is_empty() && self.devices_to_add.is_empty()
    }

    /// Total number of kernel mutations this diff implies
    /// (missing devices count as one link creation each).
    pub fn change_count(&self) -> usize {
        self.devices_to_add.len()
            + self
                .devices_to_modify
                .iter()
                .map(|(_, c)| c.change_count())
                .sum::<usize>()
    }
}

#[nlink_macros::send_futures]
impl WireguardConfigDiff {
    /// Apply this precomputed diff (#519): the config it was computed from
    /// supplies the declared values it writes. Mirrors
    /// [`ConfigDiff::apply`](crate::netlink::config::ConfigDiff::apply)
    /// and [`NftablesDiff::apply`](crate::netlink::nftables::config::NftablesDiff::apply).
    pub async fn apply(&self, conn: &Connection<Wireguard>) -> Result<WireguardApplyResult> {
        if self.is_empty() {
            return Ok(WireguardApplyResult::default());
        }
        let Some(config) = self.source.clone() else {
            return Err(crate::netlink::Error::invalid_message(
                "wireguard apply: this diff was not computed by WireguardConfig::diff",
            ));
        };
        self.apply_declared(conn, &config).await
    }

    async fn apply_declared(
        &self,
        conn: &Connection<Wireguard>,
        config: &WireguardConfig,
    ) -> Result<WireguardApplyResult> {
        if !self.devices_to_add.is_empty() {
            return Err(crate::netlink::Error::invalid_message(format!(
                "wireguard apply: declared device(s) {} do not exist; create them first \
                 (WireguardConfig::ensure_devices with a same-namespace Connection<Route>, \
                 or declare the links in a NetworkConfig/Stack)",
                self.devices_to_add.join(", ")
            )));
        }
        let mut result = WireguardApplyResult::default();

        for (ifname, changes) in &self.devices_to_modify {
            // Apply device-level changes (private_key,
            // listen_port, fwmark). All optional — only
            // fields that were declared get written.
            // Plan 232 B11 — surface as a typed error instead of
            // panicking. Invariant should hold because `diff` is
            // computed against `self`; if a future refactor lets
            // `self` mutate between the diff and apply, this
            // path returns a clean error instead of crashing the
            // caller's task.
            let declared = config
                .devices
                .iter()
                .find(|d| &d.ifname == ifname)
                .ok_or_else(|| {
                    crate::netlink::Error::invalid_message(format!(
                        "wireguard apply: diff references undeclared device `{ifname}`"
                    ))
                })?;

            if changes.has_device_level_change() {
                // Only the fields that differ, as for peers: rewriting an
                // unchanged listen port of 0 would rebind the device to a
                // fresh random port as a side effect of, say, a key change.
                conn.set_device_by_name(ifname, |mut b| {
                    if changes.private_key_set
                        && let Some(k) = declared.private_key
                    {
                        b = b.private_key(k);
                    }
                    if changes.listen_port_set
                        && let Some(p) = declared.listen_port
                    {
                        b = b.listen_port(p);
                    }
                    if changes.fwmark_set
                        && let Some(fw) = declared.fwmark
                    {
                        b = b.fwmark(fw);
                    }
                    b
                })
                .await
                .map_err(|e| {
                    e.with_object(crate::netlink::ErrorObject::WireguardDevice {
                        name: ifname.clone(),
                    })
                    .with_context(format!("set wireguard device {ifname}"))
                })?;
                result.device_writes += 1;
            }

            for added in &changes.peers_to_add {
                conn.set_peer_by_name(ifname, added.public_key, |b| added.apply_to_builder(b))
                    .await
                    .map_err(|e| peer_error(e, "add", ifname, &added.public_key))?;
                result.peer_writes += 1;
            }

            for (pk, peer_changes) in &changes.peers_to_modify {
                // Plan 232 B11 — same shape as the device lookup above.
                let declared_peer = declared
                    .peers
                    .iter()
                    .find(|p| &p.public_key == pk)
                    .ok_or_else(|| {
                        crate::netlink::Error::invalid_message(format!(
                            "wireguard apply: diff references undeclared peer for `{ifname}`"
                        ))
                    })?;
                // Removing single prefixes needs 6.16; asked once (#529).
                let removal_supported = if peer_changes.allowed_ips_removed.is_empty() {
                    false
                } else {
                    let absent = absent_prefix(&declared_peer.allowed_ips, &peer_changes.allowed_ips_removed);
                    conn.allowed_ip_removal_supported(ifname, *pk, absent).await?
                };
                conn.set_peer_by_name(ifname, *pk, |b| {
                    declared_peer.apply_changes_to_builder(b, peer_changes, removal_supported)
                })
                .await
                .map_err(|e| peer_error(e, "update", ifname, pk))?;
                result.peer_writes += 1;
            }

            for pk in &changes.peers_to_remove {
                conn.del_peer_by_name(ifname, *pk)
                    .await
                    .map_err(|e| peer_error(e, "remove", ifname, pk))?;
                result.peer_removals += 1;
            }
        }

        Ok(result)
    }
}

/// `e`, naming the peer it failed on (#526).
fn peer_error(e: crate::netlink::Error, verb: &str, ifname: &str, key: &[u8; WG_KEY_LEN]) -> crate::netlink::Error {
    let public_key = b64_encode_32(key);
    let context = format!("{verb} peer {public_key} on {ifname}");
    e.with_object(crate::netlink::ErrorObject::WireguardPeer {
        dev: ifname.to_string(),
        public_key,
    })
    .with_context(context)
}

/// No trailing newline, like `ConfigDiff`'s and `NftablesDiff`'s, so
/// `println!` prints each diff on its own lines with nothing doubled
/// (#532).
impl fmt::Display for WireguardConfigDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        self.render(&mut out)?;
        f.write_str(out.trim_end_matches('\n'))
    }
}

impl WireguardConfigDiff {
    fn render(&self, f: &mut String) -> fmt::Result {
        use fmt::Write as _;
        if self.is_empty() {
            return f.write_str("WireguardConfigDiff: no changes\n");
        }
        writeln!(
            f,
            "WireguardConfigDiff: {} kernel call(s)",
            self.change_count()
        )?;
        for ifname in &self.devices_to_add {
            writeln!(f, "  + device {ifname} (link missing — needs creation)")?;
        }
        for (ifname, changes) in &self.devices_to_modify {
            writeln!(f, "  {ifname}:")?;
            if changes.private_key_set {
                writeln!(f, "    set private_key")?;
            }
            if changes.listen_port_set {
                writeln!(f, "    set listen_port")?;
            }
            if changes.fwmark_set {
                writeln!(f, "    set fwmark")?;
            }
            for added in &changes.peers_to_add {
                writeln!(f, "    + peer {}", PublicKey(added.public_key))?;
            }
            for (pk, pc) in &changes.peers_to_modify {
                let bits = [
                    pc.preshared_key_set.then_some("preshared_key"),
                    pc.endpoint_set.then_some("endpoint"),
                    pc.persistent_keepalive_set.then_some("keepalive"),
                    pc.allowed_ips_set.then_some("allowed_ips"),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(", ");
                writeln!(f, "    ~ peer {} ({bits})", PublicKey(*pk))?;
            }
            for pk in &changes.peers_to_remove {
                writeln!(f, "    - peer {}", PublicKey(*pk))?;
            }
        }
        Ok(())
    }
}

/// What changed on a single device. Plan 196.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct DeviceChanges {
    /// The declared `private_key` differs from the kernel's, compared
    /// X25519-clamped as the kernel stores it (#410). `WG_CMD_GET_DEVICE`
    /// returns the key to privileged callers (`CAP_NET_ADMIN`).
    pub private_key_set: bool,
    /// `listen_port` differs from the kernel's current.
    pub listen_port_set: bool,
    /// `fwmark` differs from the kernel's current.
    pub fwmark_set: bool,
    /// Peers in the config but not in the kernel.
    pub peers_to_add: Vec<DeclaredWgPeer>,
    /// Per-peer mutations.
    #[cfg_attr(feature = "serde", serde(serialize_with = "diff_serde::keyed_changes"))]
    #[cfg_attr(
        feature = "schemars",
        schemars(with = "Vec<diff_serde::KeyedPeerChanges<'static>>")
    )]
    pub peers_to_modify: Vec<([u8; WG_KEY_LEN], PeerChanges)>,
    /// Peers in the kernel but not in the config.
    #[cfg_attr(feature = "serde", serde(serialize_with = "diff_serde::pubkey_vec"))]
    #[cfg_attr(feature = "schemars", schemars(with = "Vec<String>"))]
    pub peers_to_remove: Vec<[u8; WG_KEY_LEN]>,
}

/// Serialization helpers for the diff types (`serde` feature).
///
/// Policy: public keys render as base64 (the WireGuard-native
/// display form); secret material (preshared/private keys) is NEVER
/// serialized — only its presence, as a boolean.
#[cfg(feature = "serde")]
mod diff_serde {
    use serde::{Serializer, ser::SerializeSeq};

    use super::{PeerChanges, WG_KEY_LEN, b64_encode_32};

    pub(super) fn pubkey<S: Serializer>(
        key: &[u8; WG_KEY_LEN],
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&b64_encode_32(key))
    }

    pub(super) fn pubkey_vec<S: Serializer>(
        keys: &[[u8; WG_KEY_LEN]],
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(keys.len()))?;
        for k in keys {
            seq.serialize_element(&b64_encode_32(k))?;
        }
        seq.end()
    }

    /// One `peers-to-modify` entry as it serializes. The schema is derived
    /// from this type too, so the two cannot disagree (#876).
    #[derive(serde::Serialize)]
    #[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
    #[serde(rename_all = "kebab-case")]
    pub(super) struct KeyedPeerChanges<'a> {
        public_key: String,
        changes: &'a PeerChanges,
    }

    pub(super) fn keyed_changes<S: Serializer>(
        entries: &[([u8; WG_KEY_LEN], PeerChanges)],
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(entries.len()))?;
        for (pk, changes) in entries {
            seq.serialize_element(&KeyedPeerChanges {
                public_key: b64_encode_32(pk),
                changes,
            })?;
        }
        seq.end()
    }

    pub(super) fn secret_presence<S: Serializer>(
        key: &Option<[u8; WG_KEY_LEN]>,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bool(key.is_some())
    }

    pub(super) fn keepalive_secs<S: Serializer>(
        d: &Option<std::time::Duration>,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_some(&super::keepalive_secs(*d)),
            None => s.serialize_none(),
        }
    }
}

impl DeviceChanges {
    pub fn is_empty(&self) -> bool {
        !self.has_device_level_change()
            && self.peers_to_add.is_empty()
            && self.peers_to_modify.is_empty()
            && self.peers_to_remove.is_empty()
    }

    pub fn has_device_level_change(&self) -> bool {
        self.private_key_set || self.listen_port_set || self.fwmark_set
    }

    pub fn change_count(&self) -> usize {
        let device_level = self.has_device_level_change() as usize;
        device_level
            + self.peers_to_add.len()
            + self.peers_to_modify.len()
            + self.peers_to_remove.len()
    }
}

/// What changed on a single peer. Plan 196.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PeerChanges {
    pub preshared_key_set: bool,
    pub endpoint_set: bool,
    pub persistent_keepalive_set: bool,
    pub allowed_ips_set: bool,
    /// The prefixes declared that the peer does not hold (#529).
    pub allowed_ips_added: Vec<AllowedIp>,
    /// The prefixes the peer holds that are no longer declared (#529).
    pub allowed_ips_removed: Vec<AllowedIp>,
}

impl PeerChanges {
    pub fn is_empty(&self) -> bool {
        !(self.preshared_key_set
            || self.endpoint_set
            || self.persistent_keepalive_set
            || self.allowed_ips_set)
    }
}

// =============================================================================
// Apply result
// =============================================================================

/// Outcome of [`WireguardConfig::apply`]. Plan 196.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Default)]
#[must_use = "Inspect the per-kind counters to learn what apply changed"]
pub struct WireguardApplyResult {
    /// Number of `SET_DEVICE` calls issued (one per device
    /// with a device-level change).
    pub device_writes: usize,
    /// Number of `SET_PEER` calls issued (one per added or
    /// modified peer).
    pub peer_writes: usize,
    /// Number of peer-removal `SET_PEER` calls issued (one
    /// per removed peer; uses `WgPeerFlags::RemoveMe`).
    pub peer_removals: usize,
}

impl WireguardApplyResult {
    /// Total number of kernel calls this apply made.
    pub fn total_writes(&self) -> usize {
        self.device_writes + self.peer_writes + self.peer_removals
    }
}

/// Marker that this declarative module exists. Plan 196.
///
/// Suppresses an unused-import lint that would fire when
/// `Error` is only used inside doc examples — we keep the
/// import for forward use (apply errors propagate via `?`
/// in the body but the compiler doesn't see the `Error`
/// type referenced explicitly anywhere).
#[allow(dead_code)]
const _PLAN_196_MARKER: Option<Error> = None;

#[cfg(test)]
mod tests {

    /// WireGuard counts keepalive in whole seconds, and a fraction rounds
    /// up: 500 ms was 0, which turns keepalive off (#529).
    #[test]
    fn keepalive_rounds_up_to_whole_seconds() {
        use super::keepalive_secs;
        use std::time::Duration;
        assert_eq!(keepalive_secs(Duration::from_millis(500)), 1);
        assert_eq!(keepalive_secs(Duration::from_secs(25)), 25);
        assert_eq!(keepalive_secs(Duration::from_millis(25_100)), 26);
        assert_eq!(keepalive_secs(Duration::ZERO), 0);
        assert_eq!(keepalive_secs(Duration::from_secs(1 << 20)), u16::MAX);
        let too_long = super::WireguardConfig::new().device("wg0", |d| {
            d.peer([7u8; 32], |p| {
                p.persistent_keepalive(Duration::from_secs(70_000))
            })
        });
        assert!(too_long.validate().is_err());
    }

    /// The private key round-trips through base64 clamped, and never shows
    /// in `Debug` (#529, #499).
    #[test]
    fn private_key_base64_and_debug() {
        use super::PrivateKey;
        let key: PrivateKey = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
            .parse()
            .unwrap();
        assert_eq!(
            key.to_string(),
            "cAdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LGo="
        );
        let shown = format!("{key:?}");
        assert!(
            shown.contains("bytes redacted") && !shown.contains("cAdt"),
            "{shown}"
        );
        assert!("not base64".parse::<PrivateKey>().is_err());
    }

    /// RFC 7748 §6.1: Alice's public key from her private key; and a
    /// generated key is clamped and has a public key of its own.
    #[cfg(feature = "wireguard-keys")]
    #[test]
    fn private_keys_generate_and_derive_their_public_key() {
        use super::PrivateKey;
        let alice: PrivateKey = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="
            .parse()
            .unwrap();
        assert_eq!(
            alice.public_key().to_string(),
            "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
        );
        let a = PrivateKey::generate().unwrap();
        let b = PrivateKey::generate().unwrap();
        assert_ne!(a, b);
        assert_eq!(
            a,
            PrivateKey::from_bytes(*a.as_bytes()),
            "generated keys are clamped"
        );
        assert_ne!(a.public_key(), b.public_key());
    }

    /// One prefix on two peers of a device is refused, masked the way the
    /// kernel stores it; the same prefix on two devices is fine (#498).
    /// A device declared twice is refused too.
    #[test]
    fn a_prefix_on_two_peers_is_refused() {
        use std::net::Ipv4Addr;
        let tunnel = |host: u8| AllowedIp::v4(Ipv4Addr::new(10, 99, 0, host), 24);
        let shared = WireguardConfig::new().device("wg0", |d| {
            d.peer(key(1), |p| p.allowed_ip(tunnel(1)))
                .peer(key(2), |p| p.allowed_ip(tunnel(5)))
        });
        let err = shared.validate().unwrap_err().to_string();
        assert!(
            err.contains("10.99.0.0/24 is an allowed IP of two peers"),
            "{err}"
        );

        let ok = WireguardConfig::new()
            .device("wg0", |d| d.peer(key(1), |p| p.allowed_ip(tunnel(1))))
            .device("wg1", |d| d.peer(key(2), |p| p.allowed_ip(tunnel(1))));
        ok.validate().unwrap();

        let twice = WireguardConfig::new()
            .device("wg0", |d| d.peer(key(1), |p| p.allowed_ip(tunnel(1))))
            .device("wg0", |d| d.peer(key(2), |p| p.allowed_ip(tunnel(2))));
        let err = twice.validate().unwrap_err().to_string();
        assert!(err.contains("devices.wg0"), "{err}");
    }

    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use super::*;
    use crate::netlink::genl::wireguard::types::WgPeer;

    fn key(byte: u8) -> [u8; WG_KEY_LEN] {
        [byte; WG_KEY_LEN]
    }

    fn empty_device(ifname: &str) -> WgDevice {
        let mut d = WgDevice::new();
        d.ifname = Some(ifname.to_string());
        d
    }

    #[test]
    fn empty_config_diff_is_empty() {
        let cfg = WireguardConfig::new();
        assert!(cfg.devices().is_empty());
    }

    #[test]
    fn device_builder_records_fields() {
        let cfg = WireguardConfig::new().device("wg0", |d| {
            d.private_key(key(0xaa)).listen_port(51820).fwmark(0xdead)
        });
        let dev = &cfg.devices()[0];
        assert_eq!(dev.ifname, "wg0");
        assert_eq!(dev.private_key, Some(key(0xaa)));
        assert_eq!(dev.listen_port, Some(51820));
        assert_eq!(dev.fwmark, Some(0xdead));
        assert!(dev.peers.is_empty());
    }

    #[test]
    fn peer_builder_records_fields() {
        let cfg = WireguardConfig::new().device("wg0", |d| {
            d.peer(key(0xbb), |p| {
                p.endpoint(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
                    51820,
                ))
                .persistent_keepalive(Duration::from_secs(25))
                .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
            })
        });
        let peer = &cfg.devices()[0].peers[0];
        assert_eq!(peer.public_key, key(0xbb));
        assert_eq!(peer.persistent_keepalive, Some(Duration::from_secs(25)));
        assert_eq!(peer.allowed_ips.len(), 1);
    }

    /// Host bits and duplicates do not survive the kernel's trie, so they
    /// must not count as a difference; a different prefix still does.
    #[test]
    fn diff_allowed_ips_compare_masked_and_deduplicated() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| {
                p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 5), 24))
                    .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
                    .allowed_ip(AllowedIp::v6("fd00::7".parse().unwrap(), 64))
            })
            .build();
        let mut curr = empty_device("wg0");
        let mut peer = WgPeer::new(key(0xbb));
        peer.allowed_ips = vec![
            AllowedIp::v6("fd00::".parse().unwrap(), 64),
            AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24),
        ];
        curr.peers.push(peer.clone());
        let allowed_changed = |curr: &WgDevice| {
            declared
                .diff_against(curr)
                .peers_to_modify
                .iter()
                .any(|(_, pc)| pc.allowed_ips_set)
        };
        assert!(!allowed_changed(&curr));

        peer.allowed_ips[1] = AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 25);
        curr.peers[0] = peer;
        assert!(allowed_changed(&curr), "a different prefix length is a change");
    }

    /// A declared PSK is compared with the dumped one: equal is no change,
    /// different or missing is, and an all-zero declaration means none.
    #[test]
    fn diff_preshared_key_compares_with_the_dump() {
        let with_psk = |psk| {
            DeclaredWgDeviceBuilder::new("wg0".into())
                .peer(key(0xbb), |p| p.preshared_key(psk))
                .build()
        };
        let dumped = |psk: Option<[u8; WG_KEY_LEN]>| {
            let mut curr = empty_device("wg0");
            let mut peer = WgPeer::new(key(0xbb));
            peer.preshared_key = psk;
            curr.peers.push(peer);
            curr
        };
        let psk_changed = |declared: &DeclaredWgDevice, curr: &WgDevice| {
            declared
                .diff_against(curr)
                .peers_to_modify
                .iter()
                .any(|(_, pc)| pc.preshared_key_set)
        };
        assert!(!psk_changed(&with_psk(key(0x11)), &dumped(Some(key(0x11)))));
        assert!(psk_changed(&with_psk(key(0x11)), &dumped(Some(key(0x22)))));
        assert!(psk_changed(&with_psk(key(0x11)), &dumped(None)));
        assert!(!psk_changed(&with_psk([0; WG_KEY_LEN]), &dumped(None)));
    }

    /// The kernel dumps the clamped key, so an unclamped declaration
    /// matches its clamped echo and a different key still does not.
    #[test]
    fn diff_private_key_compares_clamped() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .private_key([0xaa; WG_KEY_LEN])
            .build();
        let mut curr = empty_device("wg0");
        let mut echo = [0xaa; WG_KEY_LEN];
        echo[0] = 0xa8;
        echo[31] = 0x6a;
        curr.private_key = Some(echo);
        assert!(!declared.diff_against(&curr).private_key_set);

        curr.private_key = Some(clamp_private_key([0xbb; WG_KEY_LEN]));
        assert!(declared.diff_against(&curr).private_key_set);
    }

    #[test]
    fn diff_private_key_always_dirty_when_declared() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .private_key(key(1))
            .build();
        let curr = empty_device("wg0");
        let changes = declared.diff_against(&curr);
        assert!(changes.private_key_set);
        assert!(changes.has_device_level_change());
        assert_eq!(changes.change_count(), 1);
    }

    #[test]
    fn diff_listen_port_match_emits_no_change() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .listen_port(51820)
            .build();
        let mut curr = empty_device("wg0");
        curr.listen_port = Some(51820);
        let changes = declared.diff_against(&curr);
        assert!(
            changes.is_empty(),
            "matching listen_port shouldn't be dirty"
        );
    }

    #[test]
    fn diff_listen_port_mismatch_emits_change() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .listen_port(51820)
            .build();
        let mut curr = empty_device("wg0");
        curr.listen_port = Some(12345);
        let changes = declared.diff_against(&curr);
        assert!(changes.listen_port_set);
    }

    /// 0 asks the kernel to pick; the port it picked satisfies it.
    #[test]
    fn diff_listen_port_zero_accepts_the_kernels_choice() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .listen_port(0)
            .build();
        let mut curr = empty_device("wg0");
        curr.listen_port = Some(41_234);
        assert!(!declared.diff_against(&curr).listen_port_set);
    }

    #[test]
    fn diff_peers_to_add() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| {
                p.persistent_keepalive(Duration::from_secs(25))
            })
            .build();
        let curr = empty_device("wg0");
        let changes = declared.diff_against(&curr);
        assert_eq!(changes.peers_to_add.len(), 1);
        assert_eq!(changes.peers_to_add[0].public_key, key(0xbb));
    }

    #[test]
    fn diff_peers_to_remove() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into()).build();
        let mut curr = empty_device("wg0");
        let mut p = WgPeer::new(key(0xcc));
        p.endpoint = Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            51820,
        ));
        curr.peers.push(p);
        let changes = declared.diff_against(&curr);
        assert_eq!(changes.peers_to_remove, vec![key(0xcc)]);
    }

    #[test]
    fn diff_peer_endpoint_change() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| {
                p.endpoint(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
                    51820,
                ))
            })
            .build();
        let mut curr = empty_device("wg0");
        let mut peer = WgPeer::new(key(0xbb));
        peer.endpoint = Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            51820,
        ));
        curr.peers.push(peer);
        let changes = declared.diff_against(&curr);
        assert!(
            changes
                .peers_to_modify
                .iter()
                .any(|(pk, pc)| { *pk == key(0xbb) && pc.endpoint_set })
        );
    }

    #[test]
    fn diff_peer_allowed_ips_set_difference() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| {
                p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
                    .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 1, 0), 24))
            })
            .build();
        let mut curr = empty_device("wg0");
        let mut peer = WgPeer::new(key(0xbb));
        peer.allowed_ips = vec![AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24)];
        curr.peers.push(peer);
        let changes = declared.diff_against(&curr);
        assert!(
            changes
                .peers_to_modify
                .iter()
                .any(|(_, pc)| pc.allowed_ips_set)
        );
    }

    /// #529: the diff names the prefixes that come and go, and the update
    /// sends only those where the kernel removes single prefixes — else
    /// the whole list, replaced; with nothing to remove, only additions.
    #[test]
    fn an_allowed_ip_update_sends_what_changed() {
        use crate::netlink::genl::wireguard::types::WgPeerFlags;
        let net = |n| AllowedIp::v4(Ipv4Addr::new(10, n, 0, 0), 24);
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| p.allowed_ip(net(0)).allowed_ip(net(2)))
            .build();
        let mut curr = empty_device("wg0");
        let mut peer = WgPeer::new(key(0xbb));
        peer.allowed_ips = vec![net(0), net(1)];
        curr.peers.push(peer);
        let changes = declared.diff_against(&curr);
        let (_, pc) = &changes.peers_to_modify[0];
        assert_eq!((pc.allowed_ips_added.clone(), pc.allowed_ips_removed.clone()), (vec![net(2)], vec![net(1)]));

        let declared_peer = &declared.peers[0];
        let replace = WgPeerFlags::ReplaceAllowedIps as u32;
        let new = declared_peer.apply_changes_to_builder(WgPeerBuilder::new(key(0xbb)), pc, true);
        assert_eq!(new.get_allowed_ips(), [net(2)]);
        assert_eq!(new.get_removed_allowed_ips(), [net(1)]);
        assert_eq!(new.get_flags() & replace, 0);
        let old = declared_peer.apply_changes_to_builder(WgPeerBuilder::new(key(0xbb)), pc, false);
        assert_eq!(old.get_allowed_ips(), [net(0), net(2)]);
        assert!(old.get_removed_allowed_ips().is_empty());
        assert_eq!(old.get_flags() & replace, replace);

        let mut grows = pc.clone();
        grows.allowed_ips_removed.clear();
        let added = declared_peer.apply_changes_to_builder(WgPeerBuilder::new(key(0xbb)), &grows, false);
        assert_eq!(added.get_allowed_ips(), [net(2)]);
        assert_eq!(added.get_flags() & replace, 0, "nothing to remove: nothing to replace");
    }

    /// #529: an `InitialOnly` endpoint does not snap a roamed peer back.
    #[test]
    fn an_initial_only_endpoint_is_not_enforced() {
        let at = |last| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, last)), 51820);
        let declared = |policy| {
            DeclaredWgDeviceBuilder::new("wg0".into())
                .peer(key(0xbb), move |p| p.endpoint(at(2)).endpoint_policy(policy))
                .build()
        };
        let mut curr = empty_device("wg0");
        let mut peer = WgPeer::new(key(0xbb));
        peer.endpoint = Some(at(9));
        curr.peers.push(peer);
        assert!(declared(EndpointPolicy::InitialOnly).diff_against(&curr).peers_to_modify.is_empty());
        assert!(declared(EndpointPolicy::Enforce).diff_against(&curr).peers_to_modify[0].1.endpoint_set);
    }

    #[test]
    fn diff_peer_allowed_ips_order_independent() {
        // Declaring 10.0.0.0/24 + 10.0.1.0/24 vs kernel
        // reporting the same two in opposite order — no
        // change should fire (multisets equal).
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| {
                p.allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24))
                    .allowed_ip(AllowedIp::v4(Ipv4Addr::new(10, 0, 1, 0), 24))
            })
            .build();
        let mut curr = empty_device("wg0");
        let mut peer = WgPeer::new(key(0xbb));
        peer.allowed_ips = vec![
            AllowedIp::v4(Ipv4Addr::new(10, 0, 1, 0), 24),
            AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24),
        ];
        curr.peers.push(peer);
        let changes = declared.diff_against(&curr);
        for (_, pc) in &changes.peers_to_modify {
            assert!(!pc.allowed_ips_set);
        }
    }

    // -------- PublicKey newtype --------

    #[test]
    fn public_key_round_trips_through_base64() {
        // Known WireGuard test vector.
        let s = "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0WI=";
        let pk: PublicKey = s.parse().unwrap();
        assert_eq!(pk.to_string(), s);
    }

    #[test]
    fn public_key_zero_round_trips() {
        let pk = PublicKey::from_bytes([0u8; WG_KEY_LEN]);
        let s = pk.to_string();
        assert_eq!(s.len(), 44);
        assert_eq!(s.parse::<PublicKey>().unwrap(), pk);
    }

    #[test]
    fn public_key_max_round_trips() {
        let pk = PublicKey::from_bytes([0xffu8; WG_KEY_LEN]);
        let s = pk.to_string();
        let back: PublicKey = s.parse().unwrap();
        assert_eq!(back, pk);
    }

    /// Plan 215 M12 — b64_decode_32 must accept unpadded base64.
    /// Pre-fix this would return None for the 43-char form because
    /// the gate required exactly 44 chars + trailing `=`.
    #[test]
    fn public_key_accepts_unpadded_base64() {
        let padded = "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0WI=";
        let unpadded = padded.trim_end_matches('=');
        let from_padded: PublicKey = padded.parse().unwrap();
        let from_unpadded: PublicKey = unpadded.parse().unwrap();
        assert_eq!(from_padded, from_unpadded);
    }

    #[test]
    fn public_key_rejects_wrong_length() {
        assert!("AAA=".parse::<PublicKey>().is_err());
        assert!("".parse::<PublicKey>().is_err());
        let too_long = "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0WIAAAA=";
        assert!(too_long.parse::<PublicKey>().is_err());
    }

    #[test]
    fn public_key_rejects_non_base64_chars() {
        // 44 chars but contains '!' — invalid.
        let bad = "fE/wpxQ6/M6OmF5j4dvbY3FbCEXc3KlBL2QqAYjE0W!=";
        assert!(bad.parse::<PublicKey>().is_err());
    }

    #[test]
    fn public_key_debug_uses_display() {
        let pk = PublicKey::from_bytes([0u8; WG_KEY_LEN]);
        let d = format!("{pk:?}");
        assert!(d.starts_with("PublicKey("));
    }

    // -------- WireguardConfigDiff::Display --------

    #[test]
    fn diff_display_empty_says_no_changes() {
        let d = WireguardConfigDiff::default();
        assert!(d.to_string().contains("no changes"));
    }

    #[test]
    fn diff_display_renders_peer_add_remove() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .peer(key(0xbb), |p| {
                p.persistent_keepalive(Duration::from_secs(25))
            })
            .build();
        let mut curr = empty_device("wg0");
        curr.peers.push(WgPeer::new(key(0xcc)));
        let changes = declared.diff_against(&curr);
        let mut diff = WireguardConfigDiff::default();
        diff.devices_to_modify.push(("wg0".into(), changes));
        let s = diff.to_string();
        assert!(s.contains("wg0"));
        assert!(s.contains("+ peer "));
        assert!(s.contains("- peer "));
    }

    #[test]
    fn apply_result_total_writes() {
        let r = WireguardApplyResult {
            device_writes: 2,
            peer_writes: 3,
            peer_removals: 1,
        };
        assert_eq!(r.total_writes(), 6);
    }

    #[test]
    fn diff_change_count_aggregates() {
        let declared = DeclaredWgDeviceBuilder::new("wg0".into())
            .private_key(key(1))
            .listen_port(51820)
            .peer(key(0xaa), |p| {
                p.persistent_keepalive(Duration::from_secs(25))
            })
            .build();
        let curr = empty_device("wg0");
        let changes = declared.diff_against(&curr);
        // Two kernel calls: one SET_DEVICE (carries
        // private_key + listen_port — they collapse into a
        // single device-level write) and one SET_PEER (peer
        // add). change_count counts kernel calls, not
        // dirty fields.
        assert_eq!(changes.change_count(), 2);
    }

    // ---- client() + wg-quick INI parser (#137) ----

    fn b64(byte: u8) -> String {
        b64_encode_32(&key(byte))
    }

    #[test]
    fn client_builds_single_device_single_peer() {
        let cfg = WireguardConfig::client(
            "wg0",
            key(0x11),
            key(0x22),
            "203.0.113.1:51820".parse().unwrap(),
            vec![AllowedIp::v4(Ipv4Addr::UNSPECIFIED, 0)],
            Some(Duration::from_secs(25)),
        );
        let dev = &cfg.devices()[0];
        assert_eq!(dev.ifname, "wg0");
        assert_eq!(dev.private_key, Some(key(0x11)));
        assert_eq!(dev.peers.len(), 1);
        let p = &dev.peers[0];
        assert_eq!(p.public_key, key(0x22));
        assert_eq!(p.endpoint, Some("203.0.113.1:51820".parse().unwrap()));
        assert_eq!(p.persistent_keepalive, Some(Duration::from_secs(25)));
        assert_eq!(p.allowed_ips, vec![AllowedIp::v4(Ipv4Addr::UNSPECIFIED, 0)]);
    }

    #[test]
    fn wg_quick_parses_full_profile() {
        let conf = format!(
            "# a client profile\n\
             [Interface]\n\
             PrivateKey = {}\n\
             ListenPort = 51820\n\
             FwMark = 0x1234\n\
             Address = 10.0.0.2/24   # wg-quick only, ignored\n\
             DNS = 1.1.1.1\n\
             \n\
             [Peer]\n\
             PublicKey = {}\n\
             PresharedKey = {}\n\
             Endpoint = 203.0.113.1:51820\n\
             AllowedIPs = 10.0.0.0/24, 192.168.1.5, ::/0\n\
             PersistentKeepalive = 25\n",
            b64(0x11),
            b64(0x22),
            b64(0x33),
        );
        let cfg = WireguardConfig::from_wg_quick("wg0", &conf).expect("parse");
        let dev = &cfg.devices()[0];
        assert_eq!(dev.ifname, "wg0");
        assert_eq!(dev.private_key, Some(key(0x11)));
        assert_eq!(dev.listen_port, Some(51820));
        assert_eq!(dev.fwmark, Some(0x1234));
        assert_eq!(dev.peers.len(), 1);
        let p = &dev.peers[0];
        assert_eq!(p.public_key, key(0x22));
        assert_eq!(p.preshared_key, Some(key(0x33)));
        assert_eq!(p.endpoint, Some("203.0.113.1:51820".parse().unwrap()));
        assert_eq!(p.persistent_keepalive, Some(Duration::from_secs(25)));
        assert_eq!(
            p.allowed_ips,
            vec![
                AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24),
                AllowedIp::v4(Ipv4Addr::new(192, 168, 1, 5), 32),
                AllowedIp::v6(std::net::Ipv6Addr::UNSPECIFIED, 0),
            ]
        );
    }

    #[test]
    fn wg_quick_parses_multiple_peers() {
        let conf = format!(
            "[Interface]\nPrivateKey = {}\n\
             [Peer]\nPublicKey = {}\nAllowedIPs = 10.0.0.1/32\n\
             [Peer]\nPublicKey = {}\nAllowedIPs = 10.0.0.2/32\n",
            b64(0x11),
            b64(0x22),
            b64(0x44),
        );
        let cfg = WireguardConfig::from_wg_quick("wg0", &conf).expect("parse");
        let dev = &cfg.devices()[0];
        assert_eq!(dev.peers.len(), 2);
        assert_eq!(dev.peers[0].public_key, key(0x22));
        assert_eq!(dev.peers[1].public_key, key(0x44));
    }

    #[test]
    fn wg_quick_rejects_unknown_key() {
        let conf = format!("[Interface]\nPrivateKey = {}\nBogus = 1\n", b64(0x11));
        let err = WireguardConfig::from_wg_quick("wg0", &conf).unwrap_err();
        assert!(err.to_string().contains("unknown [Interface] key"), "{err}");
    }

    #[test]
    fn wg_quick_rejects_hostname_endpoint() {
        let conf = format!(
            "[Interface]\nPrivateKey = {}\n[Peer]\nPublicKey = {}\nEndpoint = vpn.example.com:51820\n",
            b64(0x11),
            b64(0x22),
        );
        let err = WireguardConfig::from_wg_quick("wg0", &conf).unwrap_err();
        assert!(err.to_string().contains("IP:port"), "{err}");
    }

    #[test]
    fn wg_quick_rejects_peer_without_public_key() {
        let conf = format!(
            "[Interface]\nPrivateKey = {}\n[Peer]\nAllowedIPs = 10.0.0.1/32\n",
            b64(0x11),
        );
        let err = WireguardConfig::from_wg_quick("wg0", &conf).unwrap_err();
        assert!(err.to_string().contains("missing PublicKey"), "{err}");
    }

    #[test]
    fn wg_quick_keepalive_off_is_none() {
        let conf = format!(
            "[Interface]\nPrivateKey = {}\n[Peer]\nPublicKey = {}\nPersistentKeepalive = off\n",
            b64(0x11),
            b64(0x22),
        );
        let cfg = WireguardConfig::from_wg_quick("wg0", &conf).expect("parse");
        assert_eq!(cfg.devices()[0].peers[0].persistent_keepalive, None);
    }

    #[test]
    fn parse_cidr_defaults_and_bounds() {
        assert_eq!(
            parse_cidr("10.0.0.1").unwrap(),
            AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 1), 32)
        );
        assert_eq!(
            parse_cidr("::1").unwrap(),
            AllowedIp::v6("::1".parse().unwrap(), 128)
        );
        assert!(
            parse_cidr("10.0.0.0/33").is_err(),
            "v4 prefix > 32 must fail"
        );
        let _ = IpAddr::V4(Ipv4Addr::UNSPECIFIED); // keep IpAddr import used
    }

    /// #169 — diff bootstrap accounting: devices_to_add participates
    /// in is_empty/change_count/Display.
    #[test]
    fn diff_devices_to_add_accounting() {
        let mut diff = WireguardConfigDiff::default();
        assert!(diff.is_empty());
        diff.devices_to_add.push("wg0".to_string());
        assert!(!diff.is_empty());
        assert_eq!(diff.change_count(), 1);
        let rendered = diff.to_string();
        assert!(rendered.contains("wg0"), "Display names the device: {rendered}");
        assert!(rendered.contains("link missing"));
    }

    /// A diff with every field filled in, keys `0xAA`..`0xDD`.
    #[cfg(feature = "serde")]
    fn populated_diff() -> WireguardConfigDiff {
        let peer = DeclaredWgPeer {
            public_key: key(0xAA),
            preshared_key: Some(key(0xBB)),
            endpoint: Some(SocketAddr::from(([203, 0, 113, 1], 51820))),
            persistent_keepalive: Some(Duration::from_secs(25)),
            allowed_ips: vec![AllowedIp::v4(Ipv4Addr::new(10, 0, 0, 0), 24)],
            endpoint_policy: EndpointPolicy::default(),
        };
        let changes = DeviceChanges {
            private_key_set: true,
            listen_port_set: false,
            fwmark_set: false,
            peers_to_add: vec![peer],
            peers_to_modify: vec![(
                key(0xCC),
                PeerChanges {
                    endpoint_set: true,
                    ..PeerChanges::default()
                },
            )],
            peers_to_remove: vec![key(0xDD)],
        };
        let mut diff = WireguardConfigDiff::default();
        diff.devices_to_modify.push(("wg0".to_string(), changes));
        diff.devices_to_add.push("wg1".to_string());
        diff
    }

    /// #169 — serde shape: public keys as base64, secrets redacted to
    /// presence booleans, keepalive in whole seconds. Pins the JSON
    /// ABI for typed drift reporting.
    #[cfg(feature = "serde")]
    #[test]
    fn diff_serde_shape_redacts_secrets() {
        let diff = populated_diff();
        let json = serde_json::to_value(&diff).expect("serialize");
        let rendered = json.to_string();

        // No raw or base64 secret material anywhere in the output.
        assert!(
            !rendered.contains(&b64_encode_32(&key(0xBB))),
            "preshared key must not serialize"
        );
        let dev = &json["devices-to-modify"][0];
        assert_eq!(dev[0], "wg0");
        let peer_json = &dev[1]["peers-to-add"][0];
        assert_eq!(peer_json["public-key"], b64_encode_32(&key(0xAA)));
        assert_eq!(peer_json["preshared-key-set"], true);
        assert_eq!(peer_json["persistent-keepalive-secs"], 25);
        assert_eq!(peer_json["allowed-ips"][0]["cidr"], 24);
        assert_eq!(
            dev[1]["peers-to-modify"][0]["public-key"],
            b64_encode_32(&key(0xCC))
        );
        assert_eq!(dev[1]["peers-to-modify"][0]["changes"]["endpoint-set"], true);
        assert_eq!(dev[1]["peers-to-remove"][0], b64_encode_32(&key(0xDD)));
        assert_eq!(json["devices-to-add"][0], "wg1");
    }

    /// #876 — the schema describes the JSON above: keys as base64 strings,
    /// the preshared key as a presence flag, the keepalive in seconds and
    /// each modified peer as `{public-key, changes}`. It described the Rust
    /// fields instead (32 integers, a `Duration` object, a tuple).
    #[cfg(feature = "schemars")]
    #[test]
    fn diff_json_matches_its_schema() {
        use crate::netlink::config::schema_check;

        let diff = populated_diff();
        schema_check::assert_every_root_property_populated(
            &diff,
            WireguardConfigDiff::json_schema_value(),
        );
        schema_check::assert_matches_schema(&diff, WireguardConfigDiff::json_schema_value());

        // An absent preshared key and keepalive are `false` and `null`.
        let mut bare = populated_diff();
        let peer = &mut bare.devices_to_modify[0].1.peers_to_add[0];
        peer.preshared_key = None;
        peer.persistent_keepalive = None;
        peer.endpoint = None;
        schema_check::assert_matches_schema(&bare, WireguardConfigDiff::json_schema_value());
    }

    /// No trailing newline, like the other diffs' `Display` (#532).
    #[test]
    fn display_has_no_trailing_newline() {
        let empty = WireguardConfigDiff::default();
        assert_eq!(empty.to_string(), "WireguardConfigDiff: no changes");
        let mut diff = WireguardConfigDiff::default();
        diff.devices_to_add.push("wg0".to_string());
        let shown = diff.to_string();
        assert!(shown.ends_with("needs creation)"), "{shown:?}");
    }

    /// The diff shows the keepalive the kernel gets: 500 ms is 1 s, not
    /// the 0 that truncation printed (#602).
    #[cfg(feature = "serde")]
    #[test]
    fn diff_serde_rounds_a_sub_second_keepalive_up() {
        let peer = DeclaredWgPeer {
            public_key: key(0xAA),
            preshared_key: None,
            endpoint: None,
            persistent_keepalive: Some(Duration::from_millis(500)),
            allowed_ips: vec![],
            endpoint_policy: EndpointPolicy::default(),
        };
        let json = serde_json::to_value(&peer).expect("serialize");
        assert_eq!(json["persistent-keepalive-secs"], 1);
    }
}
