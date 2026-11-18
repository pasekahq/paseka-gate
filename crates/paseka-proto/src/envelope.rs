//! Gate-to-gate envelopes. On the wire a JWS compact token signed by the sender gate's key.

use serde::{Deserialize, Serialize};

use crate::mandate::AttachmentRef;
use crate::{DocId, GateId, Nonce, Sha256, UnixSecs};

/// Current envelope version.
pub const ENVELOPE_V: u32 = 1;

/// Envelope payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Envelope version.
    pub v: u32,
    /// Sender gate (its tenant public key).
    pub from: GateId,
    /// Receiver gate.
    pub to: GateId,
    /// Sender-unique message id; the receiver rejects a repeat.
    pub msg_id: Nonce,
    /// Send time, Unix seconds; the receiver enforces a freshness window.
    pub sent_at: UnixSecs,
    /// Message body.
    pub body: Body,
}

/// Envelope body. Unknown types parse as [`Body::Unknown`] and are refused by the handler.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Body {
    /// A question from the peer's agent to ours.
    Question {
        /// Conversation thread.
        thread: String,
        /// Question text.
        text: String,
    },
    /// An approved answer.
    Answer {
        /// Conversation thread.
        thread: String,
        /// Exact text the owner approved.
        text: String,
        /// Digest of `text`.
        content_sha256: Sha256,
        /// Attachments bound by digest.
        #[serde(default)]
        attachments: Vec<AttachmentRef>,
    },
    /// Shelf bytes read by the gate itself.
    Share {
        /// Conversation thread.
        thread: String,
        /// Document on a shelf open to the receiver.
        doc: DocId,
        /// Section within the document, if any.
        #[serde(default)]
        section: Option<String>,
        /// Short agent note.
        #[serde(default)]
        note: Option<String>,
        /// Document bytes, base64.
        bytes_b64: String,
    },
    /// Delivery receipt.
    Ack {
        /// Acknowledged `msg_id`.
        msg_id: Nonce,
    },
    /// A body type this build does not know.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_body_type_and_extra_fields_are_tolerated() {
        let b: Body = serde_json::from_str(r#"{"type":"poll","x":1}"#).unwrap();
        assert_eq!(b, Body::Unknown);
        let b: Body =
            serde_json::from_str(r#"{"type":"question","thread":"t","text":"hi","lang":"en"}"#)
                .unwrap();
        assert!(matches!(b, Body::Question { .. }));
    }
}
