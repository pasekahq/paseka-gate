//! Approval levels, ordered by friction.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Approval level. Ordering is friction: `A0 < A1 < A2 < A2Plus < A3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Level {
    /// Open mandate or policy, no human in the loop for this message.
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

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::A0 => "A0",
            Self::A1 => "A1",
            Self::A2 => "A2",
            Self::A2Plus => "A2+",
            Self::A3 => "A3",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Level;

    #[test]
    fn unknown_level_is_a_parse_error() {
        assert_eq!(
            serde_json::from_str::<Level>("\"A2+\"").ok(),
            Some(Level::A2Plus)
        );
        assert!(serde_json::from_str::<Level>("\"A9\"").is_err());
    }
}
