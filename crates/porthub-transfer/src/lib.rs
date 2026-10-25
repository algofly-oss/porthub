//! Native HTTP file serving and parallel/resumable downloads. Both are linked
//! into the agent; there are no helper executables or runtime package installs.
mod directory;
pub mod download;
pub mod server;
mod state;
pub mod upload;
