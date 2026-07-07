use serde::{Serialize, Deserialize};

use super::client::Ping;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ClientMessage {
    Authenticate {
        token: String,
    },
    BeginTyping {
        channel: String,
    },
    EndTyping {
        channel: String,
    },
    Subscribe {
        server_id: String,
    },
    Ping {
        data: Ping,
        responded: Option<()>,
    },

    /// Request a device-claim challenge for an E2EE device
    E2EERequestChallenge {
        device_id: String,
    },
    /// Prove possession of the device identity key: Ed25519 signature over
    /// the canonical claim payload (device_id, session_id, nonce)
    E2EEProveDevice {
        device_id: String,
        signature: String,
    },
    /// Acknowledge delivery of E2EE envelopes (deletes them server-side).
    /// Only honoured for the connection's proven device.
    E2EEAck {
        ids: Vec<String>,
    },
}
