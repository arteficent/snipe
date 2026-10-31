//! Snipe's action engine: uninstall orchestration, leftover scanning, safety (backup, quarantine,
//! undo), the inventory cache and the elevated broker that runs privileged requests.

pub mod broker;
pub mod cache;
pub mod engine;
pub mod exec;
pub mod export;
pub mod protocol;
pub mod regio;
pub mod safety;
pub mod store;
pub mod traces;
pub mod uninstall;

pub use engine::Engine;
pub use protocol::*;
