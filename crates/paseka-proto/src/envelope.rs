//! Gate-to-gate wire (PROTOCOL §10; `contracts/wire/`): envelope, receipt and error payloads.
//! On the wire envelopes and receipts are compact JWS ([`crate::jws`]).

use serde::{Deserialize, Serialize};

use crate::mandate::AttachmentMeta;
use crate::{Address, EventId, KeyId, PairingId, Sha256, ThreadId, UnixSecs, V1};

/// Envelope `type`. Authority-bearing: an unknown type is a parse error (`unsupported`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    /// A released message.
    #[serde(rename = "message")]
    Message,
    /// The inviter's owner confirmed the pairing.
    #[serde(rename = "pair.confirmed")]
    PairConfirmed,
    /// The sender removed the peer.
    #[serde(rename = "unpair")]
    Unpair,
    /// The sender rotated its key.
    #[serde(rename = "key.rotate")]
    KeyRotate,
}

/// Envelope payload with `data` of type `D`. Field order is the signed serialisation order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<D> {
    /// Contract version.
    pub v: V1,
    /// Sender address.
    pub iss: Address,
    /// Recipient address.
    pub aud: Address,
    /// Event id, unique per sender.
    pub id: EventId,
    /// Event type; MUST match `D`.
    #[serde(rename = "type")]
    pub kind: EventType,
    /// Event creation time.
    pub iat: UnixSecs,
    /// Per-type data.
    pub data: D,
}

/// The envelope fields every type shares, read before `data` is parsed by type.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct EnvelopeHead {
    /// Contract version.
    pub v: V1,
    /// Sender address.
    pub iss: Address,
    /// Recipient address.
    pub aud: Address,
    /// Event id.
    pub id: EventId,
    /// Event type.
    #[serde(rename = "type")]
    pub kind: EventType,
    /// Event creation time.
    pub iat: UnixSecs,
}

/// An attachment on the wire: metadata plus b64u bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireAttachment {
    /// Metadata bound by the mandate.
    #[serde(flatten)]
    pub meta: AttachmentMeta,
    /// The bytes, b64u.
    pub data: String,
}

/// `data` of a `message` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageData {
    /// Thread.
    pub thread: ThreadId,
    /// Event answered, if any.
    pub in_reply_to: Option<EventId>,
    /// Exact body bytes the consent covers.
    pub body: String,
    /// Attachments in order.
    pub attachments: Vec<WireAttachment>,
    /// The closed mandate, SD-JWT compact form.
    pub mandate: String,
}

/// `data` of a `pair.confirmed` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairConfirmedData {
    /// The pair request that was confirmed.
    pub request_id: PairingId,
}

/// `data` of an `unpair` event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpairData {
    /// Free text shown to the owner, at most 200 characters.
    pub reason: String,
}

/// `data` of a `key.rotate` event (PROTOCOL §10.6), signed with the sender's current key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotateData {
    /// The key that becomes current.
    pub new_key: KeyId,
    /// SHA-256 of the 32-byte public key that will follow `new_key`.
    pub next_key_sha256: Sha256,
    /// Until when the replaced key stays valid.
    pub previous_valid_until: UnixSecs,
    /// Proof of possession: a compact JWS `paseka-key-proof+jwt` over a [`KeyProof`], signed by
    /// `new_key`.
    pub proof: String,
}

/// Payload of a key proof: the rotation it proves, bound to the sender address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyProof {
    /// Contract version.
    pub v: V1,
    /// Sender address, the envelope `iss`.
    pub iss: Address,
    /// Equals `data.new_key`.
    pub new_key: KeyId,
    /// Equals `data.next_key_sha256`.
    pub next_key_sha256: Sha256,
    /// Equals `data.previous_valid_until`.
    pub previous_valid_until: UnixSecs,
}

/// A parsed envelope payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// `message`.
    Message(Envelope<MessageData>),
    /// `pair.confirmed`.
    PairConfirmed(Envelope<PairConfirmedData>),
    /// `unpair`.
    Unpair(Envelope<UnpairData>),
    /// `key.rotate`.
    KeyRotate(Envelope<KeyRotateData>),
}

impl Event {
    /// Parses an envelope payload by its `type`.
    ///
    /// # Errors
    /// A JSON error on an unknown type, an unknown or missing version, or invalid `data`.
    pub fn parse(payload: &[u8]) -> Result<Self, serde_json::Error> {
        let head: EnvelopeHead = serde_json::from_slice(payload)?;
        Ok(match head.kind {
            EventType::Message => Self::Message(serde_json::from_slice(payload)?),
            EventType::PairConfirmed => Self::PairConfirmed(serde_json::from_slice(payload)?),
            EventType::Unpair => Self::Unpair(serde_json::from_slice(payload)?),
            EventType::KeyRotate => Self::KeyRotate(serde_json::from_slice(payload)?),
        })
    }

    /// The shared fields.
    pub fn head(&self) -> EnvelopeHead {
        fn h<D>(e: &Envelope<D>) -> EnvelopeHead {
            EnvelopeHead {
                v: e.v,
                iss: e.iss.clone(),
                aud: e.aud.clone(),
                id: e.id.clone(),
                kind: e.kind,
                iat: e.iat,
            }
        }
        match self {
            Self::Message(e) => h(e),
            Self::PairConfirmed(e) => h(e),
            Self::Unpair(e) => h(e),
            Self::KeyRotate(e) => h(e),
        }
    }
}

/// Receipt `status`. Informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    /// Stored for the first time.
    Accepted,
    /// Already stored with the same bytes.
    Duplicate,
    /// A value this build does not know.
    #[serde(other)]
    Unknown,
}

/// Delivery receipt payload, signed by the receiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Contract version.
    pub v: V1,
    /// Receiver address.
    pub iss: Address,
    /// Sender address.
    pub aud: Address,
    /// Event id.
    pub id: EventId,
    /// SHA-256 of the envelope's compact JWS bytes.
    pub envelope_sha256: Sha256,
    /// Receive time.
    pub received_at: UnixSecs,
    /// Outcome.
    pub status: ReceiptStatus,
}

/// Wire error code (PROTOCOL §10.5). Informational: unknown codes are classified by HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireErrorCode {
    /// Syntax, header or data invalid.
    Malformed,
    /// Signature does not verify.
    BadSignature,
    /// Sender is not an active peer of the addressed tenant, or no such tenant.
    NotPaired,
    /// The inviter's owner has not confirmed the pairing yet.
    PairingPending,
    /// Same event id with other bytes.
    Conflict,
    /// Mandate `jti` already accepted.
    MandateReplay,
    /// Body too large.
    TooLarge,
    /// Older than the acceptance window.
    Stale,
    /// Too far in the future.
    FromFuture,
    /// Unknown event type or version.
    Unsupported,
    /// Mandate verification failed.
    MandateInvalid,
    /// Invite code unknown, used or expired.
    InviteInvalid,
    /// Peer volume limit.
    RateLimited,
    /// Unexpected failure.
    Internal,
    /// Gate not ready.
    Unavailable,
    /// A code this build does not know.
    #[serde(other)]
    Unknown,
}

impl WireErrorCode {
    /// HTTP status and whether the sender retries. `None` for [`Self::Unknown`].
    pub fn http(self) -> Option<(u16, bool)> {
        Some(match self {
            Self::Malformed => (400, false),
            Self::BadSignature => (401, false),
            Self::NotPaired => (403, false),
            Self::PairingPending => (403, true),
            Self::Conflict | Self::MandateReplay => (409, false),
            Self::TooLarge => (413, false),
            Self::Stale | Self::Unsupported | Self::MandateInvalid | Self::InviteInvalid => {
                (422, false)
            }
            Self::FromFuture => (422, true),
            Self::RateLimited => (429, true),
            Self::Internal => (500, true),
            Self::Unavailable => (503, true),
            Self::Unknown => return None,
        })
    }
}

/// Error detail of a wire error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireErrorDetail {
    /// Code.
    pub code: WireErrorCode,
    /// Human-readable text, at most 500 characters.
    pub message: String,
    /// Whether the sender retries.
    pub retryable: bool,
}

/// Wire error response body. Unsigned; serves only the retry decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireError {
    /// Detail.
    pub error: WireErrorDetail,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &str = r#"{"v":1,"iss":"t_01JD0000000000000000000001",
        "aud":"t_01JD0000000000000000000002",
        "id":"e_01JD0000000000000000000002","type":"TYPE","iat":1,"data":{"reason":"bye"}}"#;

    #[test]
    fn unknown_event_type_and_version_fail_closed() {
        assert!(matches!(
            Event::parse(MSG.replace("TYPE", "unpair").as_bytes()),
            Ok(Event::Unpair(_))
        ));
        assert!(Event::parse(MSG.replace("TYPE", "poll").as_bytes()).is_err());
        let v2 = MSG.replace("TYPE", "unpair").replace("\"v\":1", "\"v\":2");
        assert!(Event::parse(v2.as_bytes()).is_err());
    }

    #[test]
    fn unknown_error_code_maps_to_unknown() {
        let e: WireError =
            serde_json::from_str(r#"{"error":{"code":"teapot","message":"","retryable":false}}"#)
                .unwrap();
        assert_eq!(e.error.code, WireErrorCode::Unknown);
        assert_eq!(e.error.code.http(), None);
    }
}
