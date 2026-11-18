//! Draft states and the coarse reasons shown to the agent (PROTOCOL §4).

use serde::{Deserialize, Serialize};

/// Draft state. Informational for agent readers: unknown values map to [`Self::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftState {
    /// Evaluated; an approval request is out to the owner.
    AwaitingConsent,
    /// A mandate is issued; release not yet committed.
    Approved,
    /// The envelope is committed to the outbox.
    Released,
    /// The owner refused.
    Denied,
    /// The prompt TTL or the mandate `exp` passed.
    Expired,
    /// The agent withdrew it.
    Withdrawn,
    /// Policy forbids release.
    Blocked,
    /// A state this build does not know.
    #[serde(other)]
    Unknown,
}

impl DraftState {
    /// Whether no further transition is possible.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Released | Self::Denied | Self::Expired | Self::Withdrawn | Self::Blocked
        )
    }
}

/// Coarse reason of a terminal state other than `released`. Informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Denied by the owner.
    Owner,
    /// Expired.
    Timeout,
    /// Withdrawn by the agent.
    Agent,
    /// Any block.
    Policy,
    /// Unexpected failure.
    Internal,
    /// A value this build does not know.
    #[serde(other)]
    Unknown,
}

/// Delivery sub-state of a released draft. Informational.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    /// Not yet acknowledged.
    Pending,
    /// A signed receipt is stored.
    Delivered,
    /// Retry horizon passed or a non-retryable error.
    Failed,
    /// A value this build does not know.
    #[serde(other)]
    Unknown,
}

/// What the agent proposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftKind {
    /// Free text.
    FreeText,
    /// A rendered owner template.
    Template,
    /// A shelf share read by the gate.
    Share,
}
