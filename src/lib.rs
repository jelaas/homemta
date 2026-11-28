//! homemta - a minimal MTA for home servers.
//!
//! Library crate: the binary is a thin wrapper around these modules.
//! Exposed as a lib so integration tests can exercise the protocol pieces.

pub mod address;
pub mod base64;
pub mod bounce;
pub mod config;
pub mod dns;
pub mod helper;
pub mod jsonc;
pub mod log;
pub mod md5;
pub mod pem;
pub mod queue;
pub mod random;
pub mod routing;
pub mod scram;
pub mod sha256;
pub mod smtp_client;
pub mod smtp_server;
pub mod tls;
