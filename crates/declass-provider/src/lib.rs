// SPDX-License-Identifier: GPL-3.0-or-later
//! Model API layer: wire dialects (Chat Completions, Anthropic Messages, OpenAI
//! Responses), streaming, retry, credentials, local-endpoint trust and usage.

pub mod anthropic;
pub mod backends;
pub mod chat;
pub mod chatgpt;
pub mod client;
pub mod dialect;
pub mod endpoint;
pub mod error;
mod http;
pub mod image;
pub mod live;
#[cfg(any(test, feature = "test-support"))]
pub mod mock_http;
pub mod probe;
pub mod recover;
pub mod responses;
pub mod retry;
pub mod saved_key;
pub mod sse;
pub mod types;

pub use client::{ChatProvider, ProviderConfig, Role};
pub use dialect::Dialect;
pub use error::{ErrorKind, ProviderError};
pub use types::{Image, Item, Request, Response, StopReason, ToolCall, ToolSpec, Usage};

#[cfg(test)]
mod tests;
