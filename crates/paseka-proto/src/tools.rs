//! The agent-facing tool contract (MCP and plain HTTP).
//!
//! There is deliberately no approve tool: an approval cannot be expressed in this contract.

use serde::{Deserialize, Serialize};

use crate::draft::{DraftState, Flag};
use crate::mandate::AttachmentRef;
use crate::{DocId, DraftId, Level, PeerId, Sha256};

/// Names of every agent-facing tool, in listing order.
pub const TOOL_NAMES: [&str; 10] = [
    "inbox", "read", "propose", "revise", "withdraw", "status", "share", "queue", "peers",
    "journal",
];

/// One agent tool call. An unknown tool name is a parse error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "tool", content = "args", rename_all = "snake_case")]
pub enum ToolCall {
    /// List inbound messages.
    Inbox(InboxArgs),
    /// Read one inbound message.
    Read(ReadArgs),
    /// Propose an outbound draft.
    Propose(ProposeArgs),
    /// Replace the text of a draft; any approval of the old text is void.
    Revise(ReviseArgs),
    /// Withdraw a draft.
    Withdraw(DraftRef),
    /// State of a draft.
    Status(DraftRef),
    /// Send a shelf document by pointer.
    Share(ShareArgs),
    /// Own drafts waiting for the owner.
    Queue(Empty),
    /// Paired peers and their trust levels.
    Peers(Empty),
    /// Journal of the agent's own actions.
    Journal(JournalArgs),
}

/// No arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

/// `inbox` arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxArgs {
    /// Only messages after this cursor.
    #[serde(default)]
    pub after: Option<String>,
    /// Page size.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `read` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadArgs {
    /// Inbound message id.
    pub id: String,
}

/// `propose` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposeArgs {
    /// Recipient peer.
    pub to: PeerId,
    /// Exact text.
    pub text: String,
    /// Thread being answered, if any.
    #[serde(default)]
    pub thread: Option<String>,
    /// Attachments, uploaded separately and referenced by digest.
    #[serde(default)]
    pub attachments: Vec<AttachmentRef>,
}

/// `revise` arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviseArgs {
    /// Draft to revise.
    pub draft: DraftId,
    /// New exact text.
    pub text: String,
}

/// A draft reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftRef {
    /// Draft id.
    pub draft: DraftId,
}

/// `share` arguments: a pointer only; the gate reads the bytes itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareArgs {
    /// Recipient peer.
    pub to: PeerId,
    /// Document.
    pub doc: DocId,
    /// Section within the document.
    #[serde(default)]
    pub section: Option<String>,
    /// Short note, at most 200 characters, no links.
    #[serde(default)]
    pub note: Option<String>,
}

/// `journal` arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalArgs {
    /// Page size.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Result of `propose` and `revise`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposeResult {
    /// Draft id.
    pub draft: DraftId,
    /// Revision.
    pub revision: u32,
    /// Digest of the exact text.
    pub content_sha256: Sha256,
    /// Level the owner will be asked at; [`Level::A0`] means it may leave under a mandate.
    pub level: Level,
    /// Flags found.
    #[serde(default)]
    pub flags: Vec<Flag>,
    /// Resulting state.
    pub state: DraftState,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_tool_parses_and_approve_does_not() {
        let args = |name: &str| match name {
            "read" => r#"{"id":"m1"}"#,
            "propose" => r#"{"to":"bob","text":"hi"}"#,
            "revise" => r#"{"draft":"d1","text":"hi"}"#,
            "withdraw" | "status" => r#"{"draft":"d1"}"#,
            "share" => r#"{"to":"bob","doc":"notes/a.md"}"#,
            _ => "{}",
        };
        for name in TOOL_NAMES {
            let json = format!(r#"{{"tool":"{name}","args":{}}}"#, args(name));
            assert!(serde_json::from_str::<ToolCall>(&json).is_ok(), "{name}");
        }
        let approve = r#"{"tool":"approve","args":{"draft":"d1"}}"#;
        assert!(serde_json::from_str::<ToolCall>(approve).is_err());
    }
}
