//! Native HTTP file serving and parallel/resumable downloads. Both are linked
//! into core. Optional watch synchronization is shared with the standalone tool.
mod directory;
pub mod download;
pub mod progress;
#[cfg(feature = "notifications")]
pub mod notifications;
pub mod server;
mod state;
pub mod upload;

#[cfg(feature = "sync")]
pub mod sync;
