//! Wire and data types of paseka-gate. Shapes follow `contracts/`; behaviour is in
//! `docs/PROTOCOL.md`.
//!
//! Readers are tolerant (`contracts/README.md`): unknown fields are ignored and informational
//! enums fall back to `Unknown`. Authority-bearing values (`v`, JWS `alg`/`typ`, mandate `kind`,
//! levels, trust, channels, envelope `type`, decisions) fail closed. Agent tool inputs reject
//! unknown fields.

#![forbid(unsafe_code)]

pub mod draft;
pub mod envelope;
pub mod evidence;
pub mod ids;
pub mod jws;
pub mod level;
pub mod mandate;
pub mod pairing;
pub mod tools;

pub use ids::{
    DocId, DraftId, EventId, KeyId, MandateId, MessageId, Nonce, PairingId, PeerHandle, RequestId,
    Sha256, ShelfId, TemplateId, TenantId, ThreadId,
};
pub use level::{Level, OpenTrust, Trust};

/// Unix time in seconds. The core never reads a clock; callers pass `now`.
pub type UnixSecs = u64;

/// The contract major version `"v": 1`. Any other value is a parse error.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "u32", into = "u32")]
pub struct V1;

impl TryFrom<u32> for V1 {
    type Error = String;
    fn try_from(v: u32) -> Result<Self, String> {
        if v == 1 {
            Ok(Self)
        } else {
            Err(format!("unsupported contract version {v}"))
        }
    }
}

impl From<V1> for u32 {
    fn from(_: V1) -> u32 {
        1
    }
}
