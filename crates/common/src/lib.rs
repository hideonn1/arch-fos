//! Shared domain models, IPC messages, and API contracts for Arch Forward Observations System.
//!
//! This crate intentionally has zero I/O dependencies.

pub mod api;
pub mod ipc;
pub mod models;

pub use api::*;
pub use ipc::*;
pub use models::*;
