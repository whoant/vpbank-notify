//! VPBank NEO transaction notifications over the tool's own native FCM channel.
#![forbid(unsafe_code)]

pub mod bank;
pub mod config;
mod debug;
pub mod engine;
pub mod native;
pub mod prompt;
pub mod session;
pub mod state;
#[cfg(test)]
mod test_server;
