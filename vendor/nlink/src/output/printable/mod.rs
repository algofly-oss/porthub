//! Printable trait implementations for message types.
//!
//! This module provides implementations of the `Printable` trait for
//! netlink message types from `rip-netlink`.
//!
//! The implementations are automatically available when using the
//! `Printable` trait from this crate.

mod address;
mod link;
mod neighbor;
mod route;
mod tc;
