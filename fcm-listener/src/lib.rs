//! Native Firebase Cloud Messaging client: GCM check-in, FCM Web Push registration,
//! the MCS TLS transport and Web Push (`aesgcm` / `aes128gcm`) decryption.

// Generated wire schemas: preserve their protocol names and documentation.
#[allow(
    dead_code,
    clippy::enum_variant_names,
    clippy::doc_overindented_list_items
)]
mod proto {
    pub mod checkin {
        include!(concat!(env!("OUT_DIR"), "/checkin_proto.rs"));
    }
    pub mod mcs {
        include!(concat!(env!("OUT_DIR"), "/mcs_proto.rs"));
    }
}

mod error;
pub mod fcm;
pub mod firebase;
mod gcm;
mod push;

use serde::{Deserialize, Serialize};

pub use error::Error;
pub use fcm::WebPushKeys;
pub use gcm::{CheckedSession, Connection, Session};
pub use push::{DataMessage, Message, MessageStream, new_heartbeat_ack, new_heartbeat_ping};

/// Everything an application must persist to reuse a push registration across restarts.
#[derive(Clone, Serialize, Deserialize)]
pub struct Registration {
    pub fcm_token: String,
    pub gcm: Session,
    pub keys: WebPushKeys,
}
