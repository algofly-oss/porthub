//! TUN/TAP device management library.
//!
//! This crate provides a safe, strongly-typed API for creating and managing
//! TUN (network tunnel) and TAP (ethernet tunnel) devices on Linux.
//!
//! # Overview
//!
//! TUN devices operate at Layer 3 (IP) and TAP devices operate at Layer 2
//! (Ethernet). Both are virtual network interfaces that can be used for:
//!
//! - VPN implementations
//! - Network simulation
//! - Container networking
//! - Traffic capture and injection
//!
//! # Example
//!
//! ```no_run
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::tuntap::{Mode, TunTap};
//!
//! // Create a persistent TUN device
//! let tun = TunTap::builder()
//!     .name("mytun0")
//!     .mode(Mode::Tun)
//!     .persistent(true)
//!     .create()?;
//!
//! println!("Created device: {}", tun.name());
//!
//! // Create a TAP device owned by a specific user
//! let tap = TunTap::builder()
//!     .name("mytap0")
//!     .mode(Mode::Tap)
//!     .owner(1000)  // uid
//!     .group(1000)  // gid
//!     .persistent(true)
//!     .create()?;
//! # Ok(())
//! # }
//! ```
//!
//! # No async support
//!
//! There is none, and there is no `tuntap-async` feature any more.
//! It was declared in `Cargo.toml`, documented in `lib.rs`, included in
//! `full`, and gated **zero** lines: no `#[cfg(feature = "tuntap-async")]`
//! anywhere in the crate and no `create_async` symbol. The example here
//! demonstrated `create_async().await` and `tun.read(&mut buf).await`
//! against a crate name (`rip_tuntap`) that does not exist. A user who
//! enabled the feature got no async API and no way to tell whether they
//! had mistyped it (#276).
//!
//! [`TunTap`] exposes blocking `read_packet` / `write_packet`. Wrap the
//! fd in `tokio::io::unix::AsyncFd` if you need readiness-driven I/O.

mod device;
mod error;

// `list_devices` is the feature's only enumeration API and
// `TunTapInfo` its return type; neither was re-exported, so both
// carried `#[allow(dead_code)]` — the compiler already knew they
// were unreachable (#280).
pub use device::{Mode, TunTap, TunTapBuilder, TunTapFlags, TunTapInfo, list_devices};
pub use error::{Error, Result};

/// The path to the TUN device.
pub const TUN_DEVICE_PATH: &str = "/dev/net/tun";
