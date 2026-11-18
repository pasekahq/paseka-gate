//! Pairing messages (PROTOCOL §11; `contracts/pairing/`), signed as `paseka-pair+jwt`.

use serde::{Deserialize, Serialize};

use crate::{KeyId, Nonce, PairingId, Sha256, UnixSecs, V1};

/// `type` of a pair request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PairRequestType {
    /// `"pair.request"`.
    #[default]
    #[serde(rename = "pair.request")]
    PairRequest,
}

/// `type` of a pair accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PairAcceptType {
    /// `"pair.accept"`.
    #[default]
    #[serde(rename = "pair.accept")]
    PairAccept,
}

/// Invitee to inviter: redeem an invite code. Self-certifying: signed by `iss`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequest {
    /// Contract version.
    pub v: V1,
    /// Always `pair.request`.
    #[serde(rename = "type")]
    pub kind: PairRequestType,
    /// Message id.
    pub id: PairingId,
    /// Invitee key id.
    pub iss: KeyId,
    /// Inviter key id from the pair URI.
    pub aud: KeyId,
    /// Invite code.
    pub code: Nonce,
    /// Invitee endpoint, `https`.
    pub endpoint: String,
    /// Name the invitee suggests; shown as claimed by the peer.
    pub name_hint: String,
    /// Creation time.
    pub iat: UnixSecs,
}

/// Inviter to invitee: the code was consumed; the inviter's owner still has to confirm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairAccept {
    /// Contract version.
    pub v: V1,
    /// Always `pair.accept`.
    #[serde(rename = "type")]
    pub kind: PairAcceptType,
    /// Message id.
    pub id: PairingId,
    /// Inviter key id.
    pub iss: KeyId,
    /// Invitee key id.
    pub aud: KeyId,
    /// The request answered.
    pub request_id: PairingId,
    /// SHA-256 of the request's compact JWS bytes.
    pub request_sha256: Sha256,
    /// Inviter endpoint, `https`.
    pub endpoint: String,
    /// Creation time.
    pub iat: UnixSecs,
}
