//! Error types for TUN/TAP operations.

use std::io;

/// Result type for TUN/TAP operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during TUN/TAP operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Device name too long (max 15 characters).
    #[error("device name too long: {name} ({len} > 15 characters)")]
    NameTooLong {
        /// The name that was too long.
        name: String,
        /// The length of the name.
        len: usize,
    },

    /// Invalid device name.
    #[error("invalid device name: {0}")]
    InvalidName(String),

    /// Device already exists.
    #[error("device already exists: {0}")]
    DeviceExists(String),

    /// Device not found.
    #[error("device not found: {0}")]
    DeviceNotFound(String),

    /// Permission denied.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// User not found.
    #[error("user not found: {0}")]
    UserNotFound(String),

    /// Group not found.
    #[error("group not found: {0}")]
    GroupNotFound(String),

    /// No mode specified (must be TUN or TAP).
    #[error("no mode specified (must be tun or tap)")]
    NoModeSpecified,

    /// ioctl failed.
    #[error("ioctl {name} failed: {source}")]
    Ioctl {
        /// The ioctl name.
        name: &'static str,
        /// The underlying error.
        source: io::Error,
    },
}

impl Error {
    /// Create an ioctl error.
    pub fn ioctl(name: &'static str, source: io::Error) -> Self {
        Error::Ioctl { name, source }
    }
}
