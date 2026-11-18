//! Mandates: the owner's consent, signed over the hash of the exact content.
//!
//! On the wire a mandate is a JWS compact token ([`crate::jws`]) whose payload is a [`Mandate`].

use serde::{Deserialize, Serialize};

use crate::evidence::Proof;
use crate::{Level, Nonce, PeerId, Sha256, TenantId, UnixSecs};

/// A mandate payload. An unknown `kind` is a parse error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Mandate {
    /// Consent for exactly one message.
    Closed(ClosedMandate),
    /// Consent in advance for a constrained class of messages.
    Open(OpenMandate),
}

/// An attachment bound into a mandate by digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    /// File name shown to the owner.
    pub name: String,
    /// Media type shown to the owner.
    pub media_type: String,
    /// Digest of the exact attachment bytes.
    pub sha256: Sha256,
    /// Size in bytes.
    pub size: u64,
}

/// Consent for one message: these bytes, to this recipient, once.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClosedMandate {
    /// Tenant whose owner consented.
    pub tenant: TenantId,
    /// The only recipient.
    pub to: PeerId,
    /// Digest of the exact UTF-8 text bytes the owner saw.
    pub content_sha256: Sha256,
    /// Attachments, in order.
    #[serde(default)]
    pub attachments: Vec<AttachmentRef>,
    /// Level at which the owner approved.
    pub level: Level,
    /// Channel proof.
    pub proof: Proof,
    /// Gate-issued nonce, consumed on first use.
    pub nonce: Nonce,
    /// Expiry, Unix seconds.
    pub exp: UnixSecs,
}

/// Message rate limit of an open mandate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rate {
    /// Messages allowed per window.
    pub max_messages: u32,
    /// Window length in seconds.
    pub per_secs: u64,
}

/// Hard limits of an open mandate. Absent permissions default to denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraints {
    /// Allowed templates; `{name}` marks a slot. Empty means free text within the other limits.
    #[serde(default)]
    pub templates: Vec<String>,
    /// Maximum text length in bytes.
    pub max_len: u32,
    /// Whether attachments may go out under this mandate.
    #[serde(default)]
    pub attachments: bool,
    /// Whether text derived from private sources may go out under this mandate.
    #[serde(default)]
    pub private_sources: bool,
    /// Rate limit.
    pub rate: Rate,
    /// Topics the owner allowed; matched by the gate's classifier.
    #[serde(default)]
    pub topics: Vec<String>,
}

/// Consent in advance, bounded in time and by [`Constraints`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenMandate {
    /// Tenant whose owner signed.
    pub tenant: TenantId,
    /// The only recipient.
    pub to: PeerId,
    /// Hard limits.
    pub constraints: Constraints,
    /// Start of validity, Unix seconds.
    pub nbf: UnixSecs,
    /// End of validity, Unix seconds.
    pub exp: UnixSecs,
    /// Level of the approval that signed this mandate.
    pub signed_at_level: Level,
    /// Channel proof of that approval.
    pub proof: Proof,
    /// Gate-issued nonce identifying this mandate.
    pub nonce: Nonce,
}
