//! Draft lifecycle. Revising a draft voids any approval of the old text (the nonce binds the
//! old digest) and never lowers the required level.

use paseka_proto::draft::{Draft, DraftState};
use paseka_proto::{Level, Sha256};

use crate::hash::content_sha256;
use crate::risk::{Assessment, Required};

/// An illegal lifecycle step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IllegalTransition {
    /// State the draft was in.
    pub from: DraftState,
}

fn ensure_open(d: &Draft) -> Result<(), IllegalTransition> {
    if d.state.is_terminal() || d.state == DraftState::Approved {
        return Err(IllegalTransition { from: d.state });
    }
    Ok(())
}

/// Applies a fresh assessment: blocks, or waits for the owner at no less than the previous
/// level of this draft.
pub fn apply_assessment(d: &mut Draft, a: &Assessment) {
    match a.required {
        Required::Block => d.state = DraftState::Blocked,
        Required::Level(l) => {
            d.level = d.level.max(l);
            d.state = DraftState::AwaitingApproval;
        }
    }
    d.flags.clone_from(&a.flags);
}

/// Replaces the text; the caller re-assesses with [`apply_assessment`].
///
/// # Errors
/// [`IllegalTransition`] once the draft is approved or terminal.
pub fn revise(d: &mut Draft, text: String) -> Result<Sha256, IllegalTransition> {
    ensure_open(d)?;
    d.content_sha256 = content_sha256(&text);
    d.text = text;
    d.revision += 1;
    d.state = DraftState::Proposed;
    Ok(d.content_sha256)
}

/// Marks the draft approved after a mandate for `approved_sha256` at `level` verified.
///
/// # Errors
/// [`IllegalTransition`] unless the draft awaits approval with that exact digest and level.
pub fn approve(
    d: &mut Draft,
    approved_sha256: Sha256,
    level: Level,
) -> Result<(), IllegalTransition> {
    if d.state != DraftState::AwaitingApproval
        || d.content_sha256 != approved_sha256
        || level < d.level
    {
        return Err(IllegalTransition { from: d.state });
    }
    d.state = DraftState::Approved;
    Ok(())
}

/// Withdraws the draft.
///
/// # Errors
/// [`IllegalTransition`] once the draft is approved or terminal.
pub fn withdraw(d: &mut Draft) -> Result<(), IllegalTransition> {
    ensure_open(d)?;
    d.state = DraftState::Withdrawn;
    Ok(())
}

#[cfg(test)]
mod tests {
    use paseka_proto::DraftId;

    use super::*;
    use crate::testkit::{peer, tenant};

    fn draft(text: &str) -> Draft {
        Draft {
            id: DraftId::new("d1").unwrap(),
            tenant: tenant("alice"),
            to: peer("bob"),
            revision: 0,
            text: text.into(),
            attachments: vec![],
            content_sha256: content_sha256(text),
            level: Level::A1,
            flags: vec![],
            state: DraftState::Proposed,
        }
    }

    fn at(l: Level) -> Assessment {
        Assessment {
            required: Required::Level(l),
            flags: vec![],
        }
    }

    #[test]
    fn revision_never_lowers_the_level_and_voids_the_old_digest() {
        let mut d = draft("call me at https://example.org/x");
        apply_assessment(&mut d, &at(Level::A2));
        let old = d.content_sha256;
        revise(&mut d, "call me".into()).unwrap();
        apply_assessment(&mut d, &at(Level::A1));
        assert_eq!(d.level, Level::A2);
        let new = d.content_sha256;
        assert!(approve(&mut d, old, Level::A2).is_err());
        assert!(approve(&mut d, new, Level::A1).is_err());
        assert!(approve(&mut d, new, Level::A2).is_ok());
        assert!(revise(&mut d, "changed after approval".into()).is_err());
    }

    #[test]
    fn blocked_draft_cannot_be_approved() {
        let mut d = draft("x");
        apply_assessment(
            &mut d,
            &Assessment {
                required: Required::Block,
                flags: vec![],
            },
        );
        assert_eq!(d.state, DraftState::Blocked);
        let h = d.content_sha256;
        assert!(approve(&mut d, h, Level::A3).is_err());
        assert!(withdraw(&mut d).is_err());
    }
}
