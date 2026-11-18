//! Approval levels and peer trust levels. Both are authority-bearing: an unknown value is a parse
//! error.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Approval level. Ordering is friction: `A0 < A1 < A2 < A2Plus < A3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Level {
    /// Open mandate, no human in the loop for this message.
    A0,
    /// Inline button in the gate's own consent bot.
    A1,
    /// Mini App showing the exact bytes, verified by the Ed25519 third-party signature.
    A2,
    /// Mini App plus a biometric-unlocked software key.
    #[serde(rename = "A2+")]
    A2Plus,
    /// Passkey in an external browser.
    A3,
}

impl Level {
    /// The wire string, as framed into the approval challenge (PROTOCOL §3.3).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A0 => "A0",
            Self::A1 => "A1",
            Self::A2 => "A2",
            Self::A2Plus => "A2+",
            Self::A3 => "A3",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Trust level of a peer as shown to the agent (PROTOCOL §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Trust {
    /// Nothing without consent; default for a new peer.
    T0,
    /// Templates and structured answers.
    T1,
    /// Shelves.
    T2,
    /// Free text on allowed topics (later).
    T3,
}

/// The `trust` claim of an open mandate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OpenTrust {
    /// Rendered templates.
    T1,
    /// Shelf shares.
    T2,
    /// Free text on allowed topics (later).
    T3,
    /// Free text in one thread for a short window.
    #[serde(rename = "conversation")]
    Conversation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_levels_and_trusts_are_parse_errors() {
        assert_eq!(
            serde_json::from_str::<Level>("\"A2+\"").ok(),
            Some(Level::A2Plus)
        );
        assert!(serde_json::from_str::<Level>("\"A9\"").is_err());
        assert_eq!(
            serde_json::from_str::<OpenTrust>("\"conversation\"").ok(),
            Some(OpenTrust::Conversation)
        );
        assert!(serde_json::from_str::<OpenTrust>("\"T0\"").is_err());
    }
}
