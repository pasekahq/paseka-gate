//! The agent-facing tool contract (PROTOCOL §5; `contracts/agent/`).
//!
//! There is no approve, deny, mandate, pairing, trust, policy, dictionary or settings tool: such
//! a call cannot be expressed here. Inputs reject unknown fields; outputs are read tolerantly.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::draft::{DeliveryState, DraftKind, DraftState, Reason};
use crate::evidence::Channel;
use crate::mandate::AttachmentMeta;
use crate::{
    DocId, DraftId, Level, MessageId, PeerHandle, Sha256, ShelfId, TemplateId, ThreadId, Trust,
    UnixSecs,
};

/// Names of every agent-facing tool, in listing order.
pub const TOOL_NAMES: [&str; 10] = [
    "inbox", "read", "propose", "revise", "withdraw", "status", "share", "queue", "peers",
    "journal",
];

/// Maximum characters of a `share` note.
pub const MAX_NOTE_CHARS: usize = 200;

/// A rejected tool input; the gate answers `invalid_input`.
#[derive(Debug)]
pub struct InvalidInput(pub String);

impl std::fmt::Display for InvalidInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidInput {}

/// One agent tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCall {
    /// `inbox`.
    Inbox(InboxInput),
    /// `read`.
    Read(ReadInput),
    /// `propose`.
    Propose(ProposeInput),
    /// `revise`.
    Revise(ReviseInput),
    /// `withdraw`.
    Withdraw(DraftInput),
    /// `status`.
    Status(DraftInput),
    /// `share`.
    Share(ShareInput),
    /// `queue`.
    Queue(QueueInput),
    /// `peers`.
    Peers(PeersInput),
    /// `journal`.
    Journal(JournalInput),
}

impl ToolCall {
    /// Parses the MCP `tools/call` name and arguments.
    ///
    /// # Errors
    /// [`InvalidInput`] for an unknown tool name or arguments that violate the input schema.
    pub fn parse(name: &str, args: &[u8]) -> Result<Self, InvalidInput> {
        fn p<T: serde::de::DeserializeOwned>(args: &[u8]) -> Result<T, InvalidInput> {
            serde_json::from_slice(args).map_err(|e| InvalidInput(e.to_string()))
        }
        Ok(match name {
            "inbox" => Self::Inbox(p(args)?),
            "read" => Self::Read(p(args)?),
            "propose" => Self::Propose(p(args)?),
            "revise" => Self::Revise(p(args)?),
            "withdraw" => Self::Withdraw(p(args)?),
            "status" => Self::Status(p(args)?),
            "share" => Self::Share(p(args)?),
            "queue" => Self::Queue(p(args)?),
            "peers" => Self::Peers(p(args)?),
            "journal" => Self::Journal(p(args)?),
            other => return Err(InvalidInput(format!("unknown tool {other:?}"))),
        })
    }
}

/// Page size, 1 to 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Limit(u32);

impl Limit {
    /// The page size.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl Default for Limit {
    fn default() -> Self {
        Self(20)
    }
}

impl TryFrom<u32> for Limit {
    type Error = InvalidInput;
    fn try_from(n: u32) -> Result<Self, InvalidInput> {
        if (1..=100).contains(&n) {
            Ok(Self(n))
        } else {
            Err(InvalidInput("limit must be 1 to 100".into()))
        }
    }
}

impl From<Limit> for u32 {
    fn from(l: Limit) -> u32 {
        l.0
    }
}

/// `inbox` input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboxInput {
    /// Cursor from a previous `next`.
    #[serde(default)]
    pub since: Option<String>,
    /// Page size.
    #[serde(default)]
    pub limit: Option<Limit>,
    /// Only items from this peer.
    #[serde(default)]
    pub peer: Option<PeerHandle>,
}

/// `read` input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadInput {
    /// Inbox item.
    pub message_id: MessageId,
}

/// A template field value supplied by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    /// Integer field.
    Int(i64),
    /// Any other field type.
    Text(String),
}

/// A template call: the gate renders the owner-defined template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateCall {
    /// Template id.
    pub id: TemplateId,
    /// Field values, at most 32.
    pub fields: BTreeMap<String, FieldValue>,
}

/// Content of `propose` and `revise`: exactly one of `body` and `template`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Free text.
    Body(String),
    /// Template call.
    Template(TemplateCall),
}

/// An attachment uploaded by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentUpload {
    /// File name.
    pub name: String,
    /// Media type.
    pub media_type: String,
    /// Bytes, b64u.
    pub data: String,
}

/// `kind` of an agent-declared source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Declared by the agent; recorded as unverified.
    Agent,
}

/// An agent-declared source reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Always `agent`.
    pub kind: SourceKind,
    /// Free-form reference, 1 to 512 characters.
    #[serde(rename = "ref")]
    pub reference: String,
}

fn content(body: Option<String>, template: Option<TemplateCall>) -> Result<Content, InvalidInput> {
    match (body, template) {
        (Some(b), None) => Ok(Content::Body(b)),
        (None, Some(t)) if t.fields.len() <= 32 => Ok(Content::Template(t)),
        (None, Some(_)) => Err(InvalidInput("at most 32 template fields".into())),
        _ => Err(InvalidInput("exactly one of body and template".into())),
    }
}

fn attachments(a: Vec<AttachmentUpload>) -> Result<Vec<AttachmentUpload>, InvalidInput> {
    if a.len() > 8 {
        return Err(InvalidInput("at most 8 attachments".into()));
    }
    for x in &a {
        let bad = x.name.is_empty()
            || x.name.chars().count() > 128
            || x.name
                .chars()
                .any(|c| c == '/' || c == '\\' || c.is_control());
        if bad {
            return Err(InvalidInput("attachment name".into()));
        }
    }
    Ok(a)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposeRaw {
    to: PeerHandle,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    template: Option<TemplateCall>,
    #[serde(default)]
    in_reply_to: Option<MessageId>,
    #[serde(default)]
    attachments: Vec<AttachmentUpload>,
    #[serde(default)]
    sources: Vec<Source>,
}

/// `propose` input.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "ProposeRaw")]
pub struct ProposeInput {
    /// Recipient peer.
    pub to: PeerHandle,
    /// Body or template.
    pub content: Content,
    /// Inbox item answered.
    pub in_reply_to: Option<MessageId>,
    /// Attachments.
    pub attachments: Vec<AttachmentUpload>,
    /// Agent-declared sources.
    pub sources: Vec<Source>,
}

impl TryFrom<ProposeRaw> for ProposeInput {
    type Error = InvalidInput;
    fn try_from(r: ProposeRaw) -> Result<Self, InvalidInput> {
        if r.sources.len() > 32 {
            return Err(InvalidInput("at most 32 sources".into()));
        }
        Ok(Self {
            to: r.to,
            content: content(r.body, r.template)?,
            in_reply_to: r.in_reply_to,
            attachments: attachments(r.attachments)?,
            sources: r.sources,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviseRaw {
    draft_id: DraftId,
    revision: u32,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    template: Option<TemplateCall>,
    #[serde(default)]
    attachments: Vec<AttachmentUpload>,
}

/// `revise` input.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "ReviseRaw")]
pub struct ReviseInput {
    /// Draft.
    pub draft_id: DraftId,
    /// Current revision; anything else is `revision_conflict`.
    pub revision: u32,
    /// Body or template.
    pub content: Content,
    /// Attachments.
    pub attachments: Vec<AttachmentUpload>,
}

impl TryFrom<ReviseRaw> for ReviseInput {
    type Error = InvalidInput;
    fn try_from(r: ReviseRaw) -> Result<Self, InvalidInput> {
        if r.revision == 0 {
            return Err(InvalidInput("revision starts at 1".into()));
        }
        Ok(Self {
            draft_id: r.draft_id,
            revision: r.revision,
            content: content(r.body, r.template)?,
            attachments: attachments(r.attachments)?,
        })
    }
}

/// `withdraw` and `status` input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftInput {
    /// Draft.
    pub draft_id: DraftId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShareRaw {
    to: PeerHandle,
    doc: DocId,
    #[serde(default)]
    section: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    in_reply_to: Option<MessageId>,
}

/// `share` input: a pointer only; the gate reads the bytes itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "ShareRaw")]
pub struct ShareInput {
    /// Recipient peer.
    pub to: PeerHandle,
    /// Document id from `peers`.
    pub doc: DocId,
    /// Heading slug.
    pub section: Option<String>,
    /// Single-line note, at most 200 characters. Content rules are checked by the gate.
    pub note: Option<String>,
    /// Inbox item answered.
    pub in_reply_to: Option<MessageId>,
}

fn section_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

impl TryFrom<ShareRaw> for ShareInput {
    type Error = InvalidInput;
    fn try_from(r: ShareRaw) -> Result<Self, InvalidInput> {
        if r.section.as_deref().is_some_and(|s| !section_slug(s)) {
            return Err(InvalidInput("section must be a heading slug".into()));
        }
        if let Some(n) = &r.note {
            if n.chars().count() > MAX_NOTE_CHARS || n.contains(['\n', '\r']) {
                return Err(InvalidInput(
                    "note is one line of at most 200 characters".into(),
                ));
            }
        }
        Ok(Self {
            to: r.to,
            doc: r.doc,
            section: r.section,
            note: r.note,
            in_reply_to: r.in_reply_to,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueRaw {
    #[serde(default)]
    states: Vec<DraftState>,
    #[serde(default)]
    limit: Option<Limit>,
    #[serde(default)]
    since: Option<String>,
}

/// `queue` input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "QueueRaw")]
pub struct QueueInput {
    /// Only drafts in these states; empty means all.
    pub states: Vec<DraftState>,
    /// Page size.
    pub limit: Option<Limit>,
    /// Cursor.
    pub since: Option<String>,
}

impl TryFrom<QueueRaw> for QueueInput {
    type Error = InvalidInput;
    fn try_from(r: QueueRaw) -> Result<Self, InvalidInput> {
        if r.states.contains(&DraftState::Unknown) {
            return Err(InvalidInput("unknown draft state".into()));
        }
        Ok(Self {
            states: r.states,
            limit: r.limit,
            since: r.since,
        })
    }
}

/// `peers` input: no fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeersInput {}

/// `journal` input.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalInput {
    /// Cursor.
    #[serde(default)]
    pub since: Option<String>,
    /// Page size.
    #[serde(default)]
    pub limit: Option<Limit>,
}

/// Delivery of a released draft.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    /// Sub-state.
    pub state: DeliveryState,
    /// Last change.
    pub updated_at: UnixSecs,
}

/// A draft as the agent sees it. Carries no level, flag, nonce, request id or evidence (SP-8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftView {
    /// Draft.
    pub draft_id: DraftId,
    /// Current revision.
    pub revision: u32,
    /// What was proposed.
    pub kind: DraftKind,
    /// Recipient.
    pub to: PeerHandle,
    /// Thread.
    pub thread: ThreadId,
    /// Inbox item answered.
    pub in_reply_to: Option<MessageId>,
    /// State.
    pub state: DraftState,
    /// Coarse reason of a terminal state other than `released`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    /// Body of the current revision, so the agent learns an owner edit.
    pub body: String,
    /// Attachments of the current revision.
    pub attachments: Vec<AttachmentMeta>,
    /// SHA-256 of `body`.
    pub content_sha256: Sha256,
    /// Whether the owner authored the current revision.
    pub edited_by_owner: bool,
    /// Creation time.
    pub created_at: UnixSecs,
    /// Last change.
    pub updated_at: UnixSecs,
    /// End of the prompt TTL while awaiting consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<UnixSecs>,
    /// Delivery, once released.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<Delivery>,
    /// Conversation trust of the draft's thread with `to`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_trust: Option<ThreadTrust>,
}

/// Conversation trust of one thread with one peer as the agent sees it (PROTOCOL §4.4).
/// `ends_at` and `seconds_left` are present exactly when `active`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadTrust {
    /// Whether an active conversation mandate covers free-text replies in this thread.
    pub active: bool,
    /// End of that mandate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<UnixSecs>,
    /// Seconds from the output's making until `ends_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds_left: Option<u64>,
    /// Whether free text that opens a new thread goes to the owner.
    pub new_thread_needs_owner: bool,
}

/// `origin` of peer text: always `peer`, so the agent treats it as untrusted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Text from a peer.
    #[default]
    Peer,
}

/// An inbox list item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxItem {
    /// Item.
    pub message_id: MessageId,
    /// Always `peer`.
    pub origin: Origin,
    /// Sender.
    pub from: PeerHandle,
    /// Thread.
    pub thread: ThreadId,
    /// Own draft this answers, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to_draft: Option<DraftId>,
    /// Receive time.
    pub received_at: UnixSecs,
    /// First characters of the body, at most 200.
    pub preview: String,
    /// Number of attachments.
    pub attachments_count: u8,
    /// Whether `read` was called.
    pub read: bool,
    /// Level the sender's release satisfied.
    pub sender_level: Level,
    /// Conversation trust of this thread with the sender.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_trust: Option<ThreadTrust>,
}

/// An attachment of an inbound message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageAttachment {
    /// Metadata.
    #[serde(flatten)]
    pub meta: AttachmentMeta,
    /// Bytes, b64u.
    pub data: String,
}

/// A full inbound message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Item.
    pub message_id: MessageId,
    /// Always `peer`.
    pub origin: Origin,
    /// Sender.
    pub from: PeerHandle,
    /// Thread.
    pub thread: ThreadId,
    /// Own draft this answers, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to_draft: Option<DraftId>,
    /// Receive time.
    pub received_at: UnixSecs,
    /// Untrusted peer text.
    pub body: String,
    /// Attachments.
    pub attachments: Vec<MessageAttachment>,
    /// Level the sender's release satisfied.
    pub sender_level: Level,
    /// Channel of the sender's consent.
    pub sender_channel: Channel,
}

/// A document the agent may share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocView {
    /// Document id.
    pub doc: DocId,
    /// Title.
    pub title: String,
    /// Media type.
    pub media_type: String,
    /// Heading slugs.
    pub sections: Vec<String>,
}

/// A shelf open to the peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShelfView {
    /// Shelf id.
    pub shelf_id: ShelfId,
    /// Name.
    pub name: String,
    /// Documents.
    pub docs: Vec<DocView>,
}

/// Type of a template field. Informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldType {
    /// One of `values`.
    Enum,
    /// Integer in `min..=max`.
    Int,
    /// ISO date.
    Date,
    /// Short restricted text.
    ShortText,
    /// A type this build does not know.
    #[serde(other)]
    Unknown,
}

/// A template field specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSpec {
    /// Type.
    #[serde(rename = "type")]
    pub kind: FieldType,
    /// Allowed values (`enum`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    /// Minimum (`int`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<i64>,
    /// Maximum (`int`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<i64>,
    /// Maximum length (`short_text`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_len: Option<u32>,
}

/// A template the agent may fill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateView {
    /// Template id.
    pub id: TemplateId,
    /// What it says.
    pub description: String,
    /// Fields.
    pub fields: BTreeMap<String, FieldSpec>,
}

/// A paired peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerView {
    /// Handle.
    pub peer: PeerHandle,
    /// Display name.
    pub name: String,
    /// Trust level.
    pub trust: Trust,
    /// `exp` of the one active conversation mandate with this peer (PROTOCOL §4.4); the thread
    /// it covers is reported only by [`ThreadTrust`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_until: Option<UnixSecs>,
    /// Shelves open to this peer.
    pub shelves: Vec<ShelfView>,
    /// Templates allowed for this peer.
    pub templates: Vec<TemplateView>,
}

/// Journal entry kind. Informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JournalKind {
    /// `draft.proposed`.
    #[serde(rename = "draft.proposed")]
    DraftProposed,
    /// `draft.revised`.
    #[serde(rename = "draft.revised")]
    DraftRevised,
    /// `draft.withdrawn`.
    #[serde(rename = "draft.withdrawn")]
    DraftWithdrawn,
    /// `draft.released`.
    #[serde(rename = "draft.released")]
    DraftReleased,
    /// `draft.denied`.
    #[serde(rename = "draft.denied")]
    DraftDenied,
    /// `draft.expired`.
    #[serde(rename = "draft.expired")]
    DraftExpired,
    /// `draft.blocked`.
    #[serde(rename = "draft.blocked")]
    DraftBlocked,
    /// `delivery.delivered`.
    #[serde(rename = "delivery.delivered")]
    DeliveryDelivered,
    /// `delivery.failed`.
    #[serde(rename = "delivery.failed")]
    DeliveryFailed,
    /// `message.received`.
    #[serde(rename = "message.received")]
    MessageReceived,
    /// `peer.added`.
    #[serde(rename = "peer.added")]
    PeerAdded,
    /// `peer.removed`.
    #[serde(rename = "peer.removed")]
    PeerRemoved,
    /// `trust.changed`.
    #[serde(rename = "trust.changed")]
    TrustChanged,
    /// A kind this build does not know.
    #[serde(other)]
    Unknown,
}

/// One agent-visible journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Sequence number from 1.
    pub seq: u64,
    /// Time.
    pub at: UnixSecs,
    /// Kind.
    pub kind: JournalKind,
    /// Draft concerned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_id: Option<DraftId>,
    /// Inbox item concerned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    /// Peer concerned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<PeerHandle>,
}

/// `inbox` output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxOutput {
    /// Items.
    pub items: Vec<InboxItem>,
    /// Cursor for the next page.
    pub next: Option<String>,
}

/// `queue` output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueOutput {
    /// Drafts.
    pub drafts: Vec<DraftView>,
    /// Cursor for the next page.
    pub next: Option<String>,
}

/// `peers` output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeersOutput {
    /// Peers.
    pub peers: Vec<PeerView>,
}

/// `journal` output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalOutput {
    /// Entries.
    pub entries: Vec<JournalEntry>,
    /// Cursor for the next page.
    pub next: Option<String>,
}

/// Agent tool error code (PROTOCOL §5.3). Informational for readers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Schema violation, unknown field, bad note or template field.
    InvalidInput,
    /// No such id in this tenant, also for other tenants' ids.
    NotFound,
    /// `to` is not an active peer.
    UnknownPeer,
    /// Operation not allowed in the draft's state.
    InvalidState,
    /// `revision` is not current.
    RevisionConflict,
    /// Body or attachment limits exceeded.
    TooLarge,
    /// Agent rate or pending limit reached.
    RateLimited,
    /// Gate not ready.
    Unavailable,
    /// Unexpected failure; the draft is unchanged.
    Internal,
    /// A code this build does not know.
    #[serde(other)]
    Unknown,
}

impl ErrorCode {
    /// Plain-HTTP status and whether the agent may retry. `None` for [`Self::Unknown`].
    pub fn http(self) -> Option<(u16, bool)> {
        Some(match self {
            Self::InvalidInput => (400, false),
            Self::NotFound | Self::UnknownPeer => (404, false),
            Self::InvalidState | Self::RevisionConflict => (409, false),
            Self::TooLarge => (413, false),
            Self::RateLimited => (429, true),
            Self::Unavailable => (503, true),
            Self::Internal => (500, true),
            Self::Unknown => return None,
        })
    }
}

/// Error detail of a tool error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolErrorDetail {
    /// Code.
    pub code: ErrorCode,
    /// Human-readable text, at most 500 characters.
    pub message: String,
    /// Whether the agent may retry.
    pub retryable: bool,
}

/// Structured content of a tool error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolError {
    /// Detail.
    pub error: ToolErrorDetail,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_tool_parses_and_approve_does_not() {
        let args = |name: &str| match name {
            "read" => r#"{"message_id":"m_01JD0000000000000000000001"}"#,
            "propose" => r#"{"to":"bob","body":"hi"}"#,
            "revise" => r#"{"draft_id":"d_01JD0000000000000000000001","revision":1,"body":"hi"}"#,
            "withdraw" | "status" => r#"{"draft_id":"d_01JD0000000000000000000001"}"#,
            "share" => r#"{"to":"bob","doc":"doc_01JD0000000000000000000001"}"#,
            _ => "{}",
        };
        for name in TOOL_NAMES {
            assert!(
                ToolCall::parse(name, args(name).as_bytes()).is_ok(),
                "{name}"
            );
        }
        assert!(
            ToolCall::parse("approve", br#"{"draft_id":"d_01JD0000000000000000000001"}"#).is_err()
        );
    }

    #[test]
    fn proof_like_fields_are_rejected() {
        for field in ["approved", "proof", "mandate", "nonce", "evidence", "level"] {
            let json = format!(r#"{{"to":"bob","body":"hi","{field}":true}}"#);
            assert!(
                ToolCall::parse("propose", json.as_bytes()).is_err(),
                "{field}"
            );
        }
    }
}
