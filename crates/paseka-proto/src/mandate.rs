//! Mandate claims (PROTOCOL §8; `contracts/mandate/`). On the wire a mandate is an SD-JWT with
//! zero disclosures ([`crate::jws`]) whose payload is a [`ClosedMandate`] or an [`OpenMandate`].
//! Field order is the serialisation order, which the test vectors fix.

use serde::{Deserialize, Serialize};

use crate::evidence::Channel;
use crate::level::OpenTrust;
use crate::{
    Address, EventId, Level, MandateId, Nonce, Sha256, ShelfId, TemplateId, TenantId, ThreadId,
    UnixSecs, V1,
};

/// Attachment metadata, bound into digests and mandates in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    /// File name shown to the owner.
    pub name: String,
    /// Media type shown to the owner.
    pub media_type: String,
    /// Size in bytes.
    pub size: u64,
    /// Digest of the exact attachment bytes.
    pub sha256: Sha256,
}

/// `kind` of a closed mandate; any other value is a parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ClosedKind {
    /// `"closed"`.
    #[default]
    #[serde(rename = "closed")]
    Closed,
}

/// `kind` of an open mandate; any other value is a parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OpenKind {
    /// `"open"`.
    #[default]
    #[serde(rename = "open")]
    Open,
}

/// `proof` of a closed mandate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedProof {
    /// Channel that collected the consent.
    pub channel: Channel,
    /// Decision time.
    pub approved_at: UnixSecs,
    /// SHA-256 of the stored evidence bytes in the issuing gate's journal.
    pub evidence_sha256: Sha256,
    /// The open mandate an A0 release used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_mandate: Option<MandateId>,
    /// Publicly verifiable evidence (A3 only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Consent for one message: these bytes, to this recipient, once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedMandate {
    /// Contract version.
    pub v: V1,
    /// Always `closed`.
    pub kind: ClosedKind,
    /// Sender address; the same id as `tenant`.
    pub iss: Address,
    /// Sender tenant, bound into the release digest.
    pub tenant: TenantId,
    /// Recipient address.
    pub to: Address,
    /// Unique mandate id.
    pub jti: MandateId,
    /// Issue time.
    pub iat: UnixSecs,
    /// Expiry, `iat + 60`.
    pub exp: UnixSecs,
    /// The consumed request nonce, or a fresh one for A0.
    pub nonce: Nonce,
    /// Thread.
    pub thread: ThreadId,
    /// Event answered, if any.
    pub in_reply_to: Option<EventId>,
    /// Expiry of the draft, bound into the release digest; issuance must precede it.
    pub expires: UnixSecs,
    /// SHA-256 of the exact body bytes.
    pub content_sha256: Sha256,
    /// Attachment metadata in order.
    pub attachments: Vec<AttachmentMeta>,
    /// Release digest (PROTOCOL §3.2).
    pub release_digest: Sha256,
    /// Level the release satisfied.
    pub level: Level,
    /// Channel proof.
    pub proof: ClosedProof,
}

/// Whether attachments may leave under an open mandate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentRule {
    /// No attachments.
    None,
    /// Only documents read by the gate from an open shelf.
    Shelf,
}

/// Whether text derived from private sources may leave under an open mandate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateSources {
    /// Not allowed.
    Deny,
    /// Allowed.
    Allow,
}

/// Rate limits of an open mandate. At least one is set, except under conversation trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Rate {
    /// Messages over the whole lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_messages: Option<u32>,
    /// Messages per rolling hour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_hour: Option<u32>,
    /// Messages per rolling day.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_day: Option<u32>,
}

/// Hard limits of an open mandate. An absent permission is denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraints {
    /// Allowed template ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<TemplateId>,
    /// Maximum body length in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_len: Option<u32>,
    /// Attachment rule; absent means none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attachments: Option<AttachmentRule>,
    /// Private-source rule; absent means deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_sources: Option<PrivateSources>,
    /// Rate limits.
    pub rate: Rate,
    /// Allowed topics (T3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub topics: Vec<String>,
    /// Shelves open to the peer (T2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shelves: Vec<ShelfId>,
    /// The one thread (conversation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<ThreadId>,
}

/// `proof` of an open mandate: a human channel at A2 or higher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenProof {
    /// Channel that collected the consent.
    pub channel: Channel,
    /// Decision time.
    pub approved_at: UnixSecs,
    /// SHA-256 of the stored evidence bytes.
    pub evidence_sha256: Sha256,
}

/// Consent in advance for a constrained class of messages. Stays in the issuing gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenMandate {
    /// Contract version.
    pub v: V1,
    /// Always `open`.
    pub kind: OpenKind,
    /// Issuing tenant address; the same id as `tenant`.
    pub iss: Address,
    /// Issuing tenant.
    pub tenant: TenantId,
    /// The only recipient's address.
    pub to: Address,
    /// Unique mandate id.
    pub jti: MandateId,
    /// Issue time.
    pub iat: UnixSecs,
    /// Start of validity.
    pub nbf: UnixSecs,
    /// End of validity.
    pub exp: UnixSecs,
    /// Trust level this mandate grants.
    pub trust: OpenTrust,
    /// Level of the consent that created it; A2 or higher.
    pub signed_at_level: Level,
    /// Hard limits.
    pub constraints: Constraints,
    /// Channel proof.
    pub proof: OpenProof,
}
