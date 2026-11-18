//! Approval proofs: which channel approved and the channel's own evidence.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The approval channel that produced a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    /// Owner-signed open mandate or policy (A0).
    Policy,
    /// Inline button in the gate's consent bot (A1).
    TelegramButton,
    /// Telegram Mini App with exact bytes (A2).
    TelegramMiniApp,
    /// Mini App plus biometric-unlocked key (A2+).
    MiniAppBiometric,
    /// WebAuthn passkey in an external browser (A3).
    Passkey,
    /// Local CLI key held outside the agent's reach.
    CliKey,
    /// A channel this build does not know. Verification MUST reject it.
    #[serde(other)]
    Unknown,
}

/// `proof` of a mandate: `{channel, ...channel evidence}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proof {
    /// Channel that collected the consent.
    pub channel: Channel,
    /// Channel evidence, kept verbatim so the journal can show and re-check it.
    #[serde(flatten)]
    pub evidence: Map<String, Value>,
}

/// Evidence of an A1 inline-button press, as attested by Telegram's servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelegramButtonEvidence {
    /// Telegram user id of the presser.
    pub user_id: i64,
    /// `callback_query.id` of the press.
    pub callback_query_id: String,
    /// Consent message the button belonged to.
    pub message_id: i64,
}

/// Evidence of an A2 Mini App approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MiniAppEvidence {
    /// Raw `initData` query string, re-verifiable by the third-party Ed25519 signature.
    pub init_data: String,
    /// `auth_date` from `initData`, Unix seconds.
    pub auth_date: u64,
}

/// Which approval levels a channel can attest at most.
pub fn max_level(channel: Channel) -> Option<crate::Level> {
    use crate::Level;
    match channel {
        Channel::Policy => Some(Level::A0),
        Channel::TelegramButton | Channel::CliKey => Some(Level::A1),
        Channel::TelegramMiniApp => Some(Level::A2),
        Channel::MiniAppBiometric => Some(Level::A2Plus),
        Channel::Passkey => Some(Level::A3),
        Channel::Unknown => None,
    }
}
