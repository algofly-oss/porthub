//! Error types for socket diagnostics.

use std::io;

/// Result type for socket diagnostics operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during socket diagnostics operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error from the underlying socket.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Invalid netlink message received.
    #[error("invalid netlink message: {0}")]
    InvalidMessage(String),

    /// Netlink error response from the kernel.
    #[error("netlink error: {message} (errno: {errno})")]
    Netlink {
        /// The errno value from the kernel.
        errno: i32,
        /// Human-readable error message.
        message: String,
    },

    /// Unsupported address family.
    #[error("unsupported address family: {0}")]
    UnsupportedFamily(u8),

    /// Unsupported protocol.
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(u8),

    /// Buffer too small for message.
    #[error("buffer too small: need {needed} bytes, have {have}")]
    BufferTooSmall {
        /// Bytes needed.
        needed: usize,
        /// Bytes available.
        have: usize,
    },

    /// Parse error for address or other data.
    #[error("parse error: {0}")]
    Parse(String),
}

impl Error {
    /// Create a netlink error from an errno value.
    pub fn from_errno(errno: i32) -> Self {
        let message = match errno {
            libc::EPERM => "Operation not permitted".to_string(),
            libc::ENOENT => "No such socket".to_string(),
            libc::EINTR => "Interrupted system call".to_string(),
            libc::EIO => "I/O error".to_string(),
            libc::ENOMEM => "Out of memory".to_string(),
            libc::EACCES => "Permission denied".to_string(),
            libc::EBUSY => "Device or resource busy".to_string(),
            libc::ENODEV => "No such device".to_string(),
            libc::EINVAL => "Invalid argument".to_string(),
            libc::EOPNOTSUPP => "Operation not supported on socket".to_string(),
            _ => format!("Unknown error {}", errno),
        };
        Error::Netlink { errno, message }
    }
}
