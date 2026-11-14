// SPDX-License-Identifier: GPL-3.0-or-later
//! Integrity of extensions: what a skill, plugin or MCP server must be
//! (the lock file), digests of their files and of a server's tool
//! definitions, and reports of what differs. No process is started and
//! nothing is sent: callers gather what is installed and decide what to do.

pub mod content;
pub mod digest;
pub mod jcs;
pub mod launcher;
pub mod lock;
pub mod osv;
pub mod report;
pub mod sshsig;
pub mod toolset;
pub mod tree;

pub use digest::Sha256Digest;
pub use lock::{Entry, Kind, Lock, LockError, McpServer, Scope};
pub use report::{Finding, Level, Rule};
