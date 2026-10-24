//! Kobject uevent implementation for `Connection<KobjectUevent>`.
//!
//! This module provides methods for receiving kernel object events via the
//! NETLINK_KOBJECT_UEVENT protocol. These are the same events that udev uses
//! for device hotplugging.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, KobjectUevent};
//!
//! let conn = Connection::<KobjectUevent>::new()?;
//!
//! loop {
//!     let event = match conn.recv().await {
//!         Ok(event) => event,
//!         // The kernel dropped uevents under load (ENOBUFS): what was
//!         // missed is gone — re-read the state you track (for devices,
//!         // `util::uevent_trigger` re-announces them) and carry on.
//!         Err(e) if e.is_no_buffer_space() => continue,
//!         Err(e) => return Err(e.into()),
//!     };
//!     println!("[{}] {} ({})", event.action, event.devpath, event.subsystem);
//! }
//! # Ok(())
//! # }
//! ```

use std::{collections::HashMap, path::Path};

use super::{
    connection::Connection,
    error::Result,
    protocol::{KobjectUevent, ProtocolState},
    socket::NetlinkSocket,
    uevent_filter::{CompiledUeventFilter, UeventFilter},
};

/// Multicast group carrying the kernel's own uevents.
///
/// Group 2 exists too, but it belongs to udevd's rebroadcast — a
/// different wire format (a `libudev` header in front of the
/// environment block) that this module does not parse.
pub const UEVENT_GROUP: u32 = 1;

/// Receive-buffer size requested by [`Connection::<KobjectUevent>::new`].
///
/// The system default (`net.core.rmem_default`, ~208 KiB on a stock
/// kernel) is not much for this protocol: a uevent carries the
/// device's whole environment block, and a coldplug storm, a USB hub
/// enumerating, or somebody running `udevadm trigger` delivers
/// hundreds of them in a burst. Overflow costs frames — and unlike
/// every other subscriber in the crate, a uevent subscriber has no
/// dump to resync from (#252), so the loss is permanent.
///
/// 1 MiB is what udev's own monitor reaches for, scaled down to
/// something reasonable for a library default. Unprivileged callers
/// will be capped at `net.core.rmem_max`; see
/// [`NetlinkSocket::set_rcvbuf`] for how that degrades, and
/// [`Connection::rcvbuf`] for what was actually granted.
pub const DEFAULT_UEVENT_RCVBUF: usize = 1 << 20;

/// A kernel object event.
///
/// Uevents are text-based messages containing KEY=VALUE pairs that describe
/// device state changes. The kernel broadcasts these when devices are added,
/// removed, or their state changes.
#[derive(Debug, Clone)]
pub struct Uevent {
    /// Action type: "add", "remove", "change", "move", "online", "offline", "bind", "unbind".
    pub action: String,
    /// Device path in sysfs (e.g., "/devices/pci0000:00/0000:00:14.0/usb1/1-1").
    pub devpath: String,
    /// Subsystem name (e.g., "usb", "block", "net", "input").
    pub subsystem: String,
    /// All environment variables as key-value pairs.
    ///
    /// Common keys include:
    /// - `DEVNAME`: Device node name (e.g., "sda", "ttyUSB0")
    /// - `DEVTYPE`: Device type (e.g., "disk", "partition", "usb_device")
    /// - `DRIVER`: Driver name
    /// - `MAJOR`/`MINOR`: Device numbers
    /// - `SEQNUM`: Event sequence number
    pub env: HashMap<String, String>,
}

impl Uevent {
    /// Parse a uevent from raw message data.
    ///
    /// Uevent format: header@devpath\0KEY=VALUE\0KEY=VALUE\0...
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Find the header (action@devpath)
        let first_null = data.iter().position(|&b| b == 0)?;
        let header = std::str::from_utf8(&data[..first_null]).ok()?;

        // Parse action@devpath
        let at_pos = header.find('@')?;
        let action = header[..at_pos].to_string();
        let devpath = header[at_pos + 1..].to_string();

        // Parse KEY=VALUE pairs
        let mut env = HashMap::new();
        let mut subsystem = String::new();

        let mut offset = first_null + 1;
        while offset < data.len() {
            // Find next null terminator
            let end = data[offset..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| offset + p)
                .unwrap_or(data.len());

            if end > offset
                && let Ok(kv) = std::str::from_utf8(&data[offset..end])
                && let Some(eq_pos) = kv.find('=')
            {
                let key = &kv[..eq_pos];
                let value = &kv[eq_pos + 1..];
                if key == "SUBSYSTEM" {
                    subsystem = value.to_string();
                }
                env.insert(key.to_string(), value.to_string());
            }

            offset = end + 1;
        }

        Some(Self {
            action,
            devpath,
            subsystem,
            env,
        })
    }

    /// Get the device name if available (e.g., "sda1", "eth0").
    pub fn devname(&self) -> Option<&str> {
        self.env.get("DEVNAME").map(|s| s.as_str())
    }

    /// Get the device type if available (e.g., "disk", "partition").
    pub fn devtype(&self) -> Option<&str> {
        self.env.get("DEVTYPE").map(|s| s.as_str())
    }

    /// Get the driver name if available.
    pub fn driver(&self) -> Option<&str> {
        self.env.get("DRIVER").map(|s| s.as_str())
    }

    /// Get the major device number if available.
    pub fn major(&self) -> Option<u32> {
        self.env.get("MAJOR").and_then(|s| s.parse().ok())
    }

    /// Get the minor device number if available.
    pub fn minor(&self) -> Option<u32> {
        self.env.get("MINOR").and_then(|s| s.parse().ok())
    }

    /// Get the event sequence number.
    pub fn seqnum(&self) -> Option<u64> {
        self.env.get("SEQNUM").and_then(|s| s.parse().ok())
    }

    /// Check if this is an "add" event.
    pub fn is_add(&self) -> bool {
        self.action == "add"
    }

    /// Check if this is a "remove" event.
    pub fn is_remove(&self) -> bool {
        self.action == "remove"
    }

    /// Check if this is a "change" event.
    pub fn is_change(&self) -> bool {
        self.action == "change"
    }

    /// Check if this is a "bind" event (driver bound to device).
    pub fn is_bind(&self) -> bool {
        self.action == "bind"
    }

    /// Check if this is an "unbind" event (driver unbound from device).
    pub fn is_unbind(&self) -> bool {
        self.action == "unbind"
    }
}

#[nlink_macros::send_futures]
impl Connection<KobjectUevent> {
    /// Create a new uevent connection subscribed to kernel events.
    ///
    /// The receive buffer is sized up to [`DEFAULT_UEVENT_RCVBUF`]
    /// before the multicast subscription is taken out, so the socket
    /// is never briefly subscribed at the small default size. Use
    /// [`Self::with_rcvbuf`] to pick a different size.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, KobjectUevent};
    ///
    /// let conn = Connection::<KobjectUevent>::new()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Result<Self> {
        Self::with_rcvbuf(DEFAULT_UEVENT_RCVBUF)
    }

    /// Like [`Self::new`], with an explicit receive-buffer request.
    ///
    /// Best-effort: the kernel doubles the request and clamps it to
    /// `net.core.rmem_max` unless the caller holds `CAP_NET_ADMIN`.
    /// [`Self::rcvbuf`] reports what was granted.
    pub fn with_rcvbuf(bytes: usize) -> Result<Self> {
        let socket = NetlinkSocket::new(KobjectUevent::PROTOCOL)?;
        // Before add_membership: no window where events are arriving
        // into an undersized buffer.
        socket.set_rcvbuf(bytes)?;
        socket.add_membership(UEVENT_GROUP)?;
        Ok(Self::from_parts(socket, KobjectUevent))
    }

    /// The granted receive-buffer size — the kernel's `sk_rcvbuf`,
    /// i.e. twice the accepted request. Compare against
    /// `2 * DEFAULT_UEVENT_RCVBUF` to see whether the request was
    /// capped.
    pub fn rcvbuf(&self) -> Result<usize> {
        self.socket().rcvbuf()
    }

    /// Like [`Self::new`], for a network namespace named under
    /// `/var/run/netns`.
    ///
    /// Net-device uevents are delivered to the network namespace of
    /// the listening socket, so this sees the devices in `name` and
    /// not the host's. Uevents for every *other* subsystem go to every
    /// network namespace owned by the initial user namespace
    /// (`uevent_sock_list`) — so a namespace `ip netns add` made sees
    /// them too, and one made inside a user namespace (a rootless
    /// container) does not. See [`crate::netlink::netdev`] for what
    /// that means for a lifecycle join.
    pub fn in_namespace(name: &str) -> Result<Self> {
        Self::in_namespace_path(Path::new(super::namespace::NETNS_RUN_DIR).join(name))
    }

    /// Like [`Self::in_namespace`], for any namespace file path — a
    /// named namespace, `/proc/<pid>/ns/net`, or a bind mount the
    /// application owns.
    pub fn in_namespace_path<T: AsRef<Path>>(ns_path: T) -> Result<Self> {
        let socket = NetlinkSocket::new_in_namespace_path(KobjectUevent::PROTOCOL, ns_path)?;
        socket.set_rcvbuf(DEFAULT_UEVENT_RCVBUF)?;
        socket.add_membership(UEVENT_GROUP)?;
        Ok(Self::from_parts(socket, KobjectUevent))
    }

    /// (Re-)join the kernel uevent multicast group.
    ///
    /// Every constructor here subscribes already, and there is no way
    /// to build an unsubscribed `Connection<KobjectUevent>` — the
    /// generic namespace helpers need `P: Default`, which this
    /// protocol deliberately does not implement for exactly that
    /// reason.
    ///
    /// So this pairs with `drop_membership` for pause/resume: a
    /// monitor about to do a long stretch of work can leave the group
    /// rather than let events pile up in a buffer it isn't draining,
    /// then rejoin. Idempotent, so resuming twice is harmless.
    ///
    /// Note what pausing costs: uevents missed while unsubscribed are
    /// gone, and this is the one source with no dump to recover them
    /// from (#252). Leaving the group is only better than falling
    /// behind if you did not want those events at all.
    ///
    /// ```no_run
    /// use nlink::netlink::{Connection, KobjectUevent, uevent::UEVENT_GROUP};
    ///
    /// let conn = Connection::<KobjectUevent>::new()?;
    /// conn.socket().drop_membership(UEVENT_GROUP)?;   // pause
    /// // ... work that must not be interleaved with event handling ...
    /// conn.subscribe()?;                              // resume
    /// # Ok::<(), nlink::Error>(())
    /// ```
    pub fn subscribe(&self) -> Result<()> {
        self.socket().add_membership(UEVENT_GROUP)
    }

    /// Compile `filter` and attach it to the socket, so the kernel
    /// drops uninteresting events before they are queued.
    ///
    /// Returns the compiled program;
    /// [`CompiledUeventFilter::is_exact`] tells you whether the kernel
    /// evaluates the whole filter or only part of it. Either way the
    /// program is an over-approximation — pair this with
    /// [`Self::recv_matching`], or apply
    /// [`UeventFilter::matches`] yourself, so the criteria the kernel
    /// could not lower are still honoured.
    ///
    /// A filter with nothing to lower attaches nothing and returns an
    /// empty program; any previously attached filter is left alone, so
    /// use [`Self::clear_filter`] to remove one.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, KobjectUevent};
    /// use nlink::netlink::uevent_filter::UeventFilter;
    ///
    /// let conn = Connection::<KobjectUevent>::new()?;
    /// let filter = UeventFilter::new().subsystem("net").build();
    /// conn.attach_filter(&filter)?;
    ///
    /// loop {
    ///     let event = match conn.recv_matching(&filter).await {
    ///         Ok(event) => event,
    ///         // Uevents dropped under load: carry on (see the module docs).
    ///         Err(e) if e.is_no_buffer_space() => continue,
    ///         Err(e) => return Err(e.into()),
    ///     };
    ///     println!("{} {}", event.action, event.devpath);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "attach_filter"))]
    pub fn attach_filter(&self, filter: &UeventFilter) -> Result<CompiledUeventFilter> {
        let compiled = filter.compile();
        if !compiled.is_empty() {
            self.socket().attach_filter(compiled.program())?;
            tracing::debug!(
                instructions = compiled.len(),
                exact = compiled.is_exact(),
                "attached uevent socket filter"
            );
        }
        Ok(compiled)
    }

    /// Remove any attached socket filter. A no-op when none is
    /// attached.
    pub fn clear_filter(&self) -> Result<()> {
        self.socket().detach_filter()
    }

    /// Receive the next uevent from the kernel.
    ///
    /// Blocks until an event arrives. Unparseable frames are skipped.
    ///
    /// If a filter is attached, this yields the *kernel's* verdict,
    /// which over-accepts by design — use [`Self::recv_matching`] to
    /// apply the filter's own criteria too.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use nlink::netlink::{Connection, KobjectUevent};
    ///
    /// let conn = Connection::<KobjectUevent>::new()?;
    ///
    /// loop {
    ///     let event = match conn.recv().await {
    ///         Ok(event) => event,
    ///         // Uevents dropped under load: carry on (see the module docs).
    ///         Err(e) if e.is_no_buffer_space() => continue,
    ///         Err(e) => return Err(e.into()),
    ///     };
    ///     if event.is_add() && event.subsystem == "usb" {
    ///         println!("USB device added: {:?}", event.devname());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "recv"))]
    pub async fn recv(&self) -> Result<Uevent> {
        loop {
            let data = self.socket().recv_msg().await?;

            if let Some(event) = Uevent::parse(&data) {
                return Ok(event);
            }
            // Invalid message, try again
        }
    }

    /// Receive the next uevent that `filter` accepts.
    ///
    /// The authoritative half of the filtering story: the kernel
    /// program (if attached) sheds most of the traffic, and this
    /// applies [`UeventFilter::matches`] to what survives, so the
    /// caller sees exactly what they asked for regardless of how much
    /// of the filter could be lowered.
    ///
    /// Correct — just less efficient — with no filter attached at all.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "recv_matching"))]
    pub async fn recv_matching(&self, filter: &UeventFilter) -> Result<Uevent> {
        loop {
            let event = self.recv().await?;
            if filter.matches(&event) {
                return Ok(event);
            }
        }
    }

    /// Receive a uevent if one is already queued, without waiting.
    ///
    /// Returns `Ok(None)` when the socket is empty. Frames that fail
    /// to parse are skipped, so `Ok(None)` means "nothing readable
    /// right now", not "nothing arrived".
    ///
    /// Prefer [`Self::recv`]; this exists for callers driving their
    /// own loop that must not block, and for draining a backlog after
    /// a burst.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "try_recv"))]
    pub fn try_recv(&self) -> Result<Option<Uevent>> {
        loop {
            let Some(data) = self.socket().try_recv_msg()? else {
                return Ok(None);
            };
            if let Some(event) = Uevent::parse(&data) {
                return Ok(Some(event));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uevent() {
        // Simulated uevent message
        let msg = b"add@/devices/pci0000:00/0000:00:14.0/usb1/1-1\0ACTION=add\0DEVPATH=/devices/pci0000:00/0000:00:14.0/usb1/1-1\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0SEQNUM=12345\0";

        let event = Uevent::parse(msg).unwrap();
        assert_eq!(event.action, "add");
        assert_eq!(event.devpath, "/devices/pci0000:00/0000:00:14.0/usb1/1-1");
        assert_eq!(event.subsystem, "usb");
        assert_eq!(event.devtype(), Some("usb_device"));
        assert_eq!(event.seqnum(), Some(12345));
        assert!(event.is_add());
        assert!(!event.is_remove());
    }

    #[test]
    fn parse_uevent_with_devname() {
        let msg = b"add@/devices/virtual/block/loop0\0ACTION=add\0DEVPATH=/devices/virtual/block/loop0\0SUBSYSTEM=block\0DEVNAME=loop0\0DEVTYPE=disk\0MAJOR=7\0MINOR=0\0";

        let event = Uevent::parse(msg).unwrap();
        assert_eq!(event.subsystem, "block");
        assert_eq!(event.devname(), Some("loop0"));
        assert_eq!(event.major(), Some(7));
        assert_eq!(event.minor(), Some(0));
    }
}
