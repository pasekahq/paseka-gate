//! Per-peer trust levels and the release decision they lead to.

use paseka_proto::Level;
use paseka_proto::draft::FlagKind;

use crate::risk::{Assessment, Required};

/// Trust the owner granted a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {
    /// Nothing leaves without consent. Default for a new peer.
    T0,
    /// Templates and structured answers may leave under an open mandate.
    T1,
    /// Shelf documents open to the peer may leave by pointer.
    T2,
    /// Free text on allowed topics may leave under an open mandate.
    T3,
}

/// What the agent asked to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outbound {
    /// Free text.
    FreeText,
    /// Template or structured output.
    Structured,
    /// A shelf pointer the gate already checked against the peer's open shelves.
    SharePointer,
}

/// What happens to a draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Leaves without a human, under the peer's trust and a verified open mandate.
    Auto,
    /// Waits for the owner at this level.
    Ask(Level),
    /// Never leaves.
    Block,
}

/// Flags that always force manual approval at T3.
const T3_MANUAL: [FlagKind; 4] = [
    FlagKind::Secret,
    FlagKind::Fingerprint,
    FlagKind::Attachment,
    FlagKind::SensitiveSource,
];

/// Decides the fate of a draft.
///
/// `covered` says a verified, active open mandate admitted this message (for a share pointer:
/// the shelf check passed). Free text is never auto-released below T3, and never with a flag.
pub fn decide(trust: Trust, what: Outbound, risk: &Assessment, covered: bool) -> Decision {
    let level = match risk.required {
        Required::Block => return Decision::Block,
        Required::Level(l) => l,
    };
    let clean = risk.flags.is_empty();
    let auto = covered
        && clean
        && match what {
            Outbound::Structured => trust >= Trust::T1 && level == Level::A0,
            Outbound::SharePointer => trust >= Trust::T2,
            Outbound::FreeText => trust == Trust::T3 && level <= Level::A1,
        };
    if auto {
        return Decision::Auto;
    }
    let floor = if what == Outbound::FreeText
        || (trust == Trust::T3 && risk.flags.iter().any(|f| T3_MANUAL.contains(&f.kind)))
    {
        Level::A1
    } else {
        Level::A0
    };
    Decision::Ask(level.max(floor).max(Level::A1))
}

#[cfg(test)]
mod tests {
    use paseka_proto::draft::Flag;

    use super::*;

    fn risk(required: Required, flags: &[FlagKind]) -> Assessment {
        Assessment {
            required,
            flags: flags
                .iter()
                .map(|&kind| Flag {
                    kind,
                    start: None,
                    end: None,
                    detail: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn t0_never_releases_without_consent() {
        for what in [
            Outbound::FreeText,
            Outbound::Structured,
            Outbound::SharePointer,
        ] {
            let d = decide(
                Trust::T0,
                what,
                &risk(Required::Level(Level::A0), &[]),
                true,
            );
            assert!(matches!(d, Decision::Ask(_)), "{what:?}");
        }
    }

    #[test]
    fn structured_output_under_mandate_is_auto_from_t1() {
        let r = risk(Required::Level(Level::A0), &[]);
        assert_eq!(
            decide(Trust::T1, Outbound::Structured, &r, true),
            Decision::Auto
        );
        assert_eq!(
            decide(Trust::T1, Outbound::Structured, &r, false),
            Decision::Ask(Level::A1)
        );
        assert_eq!(
            decide(
                Trust::T1,
                Outbound::FreeText,
                &risk(Required::Level(Level::A1), &[]),
                true
            ),
            Decision::Ask(Level::A1)
        );
    }

    #[test]
    fn share_pointer_is_auto_from_t2_only() {
        let r = risk(Required::Level(Level::A0), &[]);
        assert_eq!(
            decide(Trust::T1, Outbound::SharePointer, &r, true),
            Decision::Ask(Level::A1)
        );
        assert_eq!(
            decide(Trust::T2, Outbound::SharePointer, &r, true),
            Decision::Auto
        );
        let flagged_note = risk(Required::Level(Level::A2), &[FlagKind::Link]);
        assert_eq!(
            decide(Trust::T2, Outbound::SharePointer, &flagged_note, true),
            Decision::Ask(Level::A2)
        );
    }

    #[test]
    fn t3_free_text_is_auto_only_when_clean() {
        let clean = risk(Required::Level(Level::A1), &[]);
        assert_eq!(
            decide(Trust::T3, Outbound::FreeText, &clean, true),
            Decision::Auto
        );
        let secret = risk(Required::Level(Level::A2), &[FlagKind::Secret]);
        assert_eq!(
            decide(Trust::T3, Outbound::FreeText, &secret, true),
            Decision::Ask(Level::A2)
        );
    }

    #[test]
    fn block_wins_at_every_trust_level() {
        let r = risk(Required::Block, &[FlagKind::Canary]);
        for t in [Trust::T0, Trust::T1, Trust::T2, Trust::T3] {
            assert_eq!(decide(t, Outbound::FreeText, &r, true), Decision::Block);
        }
    }
}
