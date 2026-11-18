//! Outbound drafts and their lifecycle.

use serde::{Deserialize, Serialize};

use crate::mandate::AttachmentRef;
use crate::{DraftId, Level, PeerId, Sha256, TenantId};

/// Lifecycle state of a draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftState {
    /// Proposed by the agent, not yet assessed.
    Proposed,
    /// Assessed, waiting for the owner at the given level.
    AwaitingApproval,
    /// Approved by a valid mandate, queued for delivery.
    Approved,
    /// Delivered to the peer gate.
    Sent,
    /// Withdrawn by the agent.
    Withdrawn,
    /// Refused by the owner.
    Refused,
    /// Blocked by a hard rule (canary, secret); no approval can release it.
    Blocked,
    /// Approval window passed.
    Expired,
}

impl DraftState {
    /// Whether no further transition is possible.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Sent | Self::Withdrawn | Self::Refused | Self::Blocked | Self::Expired
        )
    }
}

/// Kind of a risk flag shown on the approval screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagKind {
    /// URL or scheme link.
    Link,
    /// Long base64-looking run.
    Base64Blob,
    /// Long hex run.
    HexBlob,
    /// Long digit run (phones, ids, account numbers).
    LongNumber,
    /// Luhn-valid card number.
    CardNumber,
    /// Checksum-valid IBAN.
    Iban,
    /// API key, token or private key.
    Secret,
    /// Invisible or bidirectional control character.
    InvisibleChar,
    /// Text longer than the limit.
    TooLong,
    /// Has attachments.
    Attachment,
    /// Recipient never received anything before.
    NewRecipient,
    /// Owner dictionary term.
    Dictionary,
    /// Near-verbatim match of a sensitive-folder fingerprint.
    Fingerprint,
    /// Sensitive source read during the peer turn (MCP log).
    SensitiveSource,
    /// Owner canary marker. Always blocks.
    Canary,
    /// A flag kind this build does not know.
    #[serde(other)]
    Unknown,
}

/// A risk flag with the byte range it covers in the text, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flag {
    /// Kind.
    pub kind: FlagKind,
    /// Byte offset of the match start.
    #[serde(default)]
    pub start: Option<usize>,
    /// Byte offset of the match end.
    #[serde(default)]
    pub end: Option<usize>,
    /// Short owner-facing detail; never the matched secret itself.
    #[serde(default)]
    pub detail: String,
}

/// An outbound draft as stored by the gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Draft {
    /// Id.
    pub id: DraftId,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Recipient.
    pub to: PeerId,
    /// Revision, incremented by every `revise`.
    pub revision: u32,
    /// Exact text.
    pub text: String,
    /// Attachments.
    #[serde(default)]
    pub attachments: Vec<AttachmentRef>,
    /// Digest of `text`.
    pub content_sha256: Sha256,
    /// Required approval level.
    pub level: Level,
    /// Flags found by the risk evaluation.
    #[serde(default)]
    pub flags: Vec<Flag>,
    /// State.
    pub state: DraftState,
}
