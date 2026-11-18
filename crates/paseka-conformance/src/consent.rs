//! Attacks on the consent path: drafts, approval requests and decisions (SP-2 to SP-7, SP-16).

use paseka_core::draft::{DecisionAttempt, DecisionError, DraftError};
use paseka_core::risk::Required;
use paseka_proto::draft::{DraftState, Reason};
use paseka_proto::evidence::Channel;
use paseka_proto::mandate::AttachmentMeta;
use paseka_proto::{Level, Sha256};

use crate::world::{BODY, NOW, TTL, approve, draft, revision, seed, tenant};
use crate::{Outcome, all, expect};

pub(crate) fn ca03_unanswered_prompt_expires() -> Outcome {
    let mut d = draft(BODY, Required::Level(Level::A1));
    d.expire(NOW + TTL);
    match (d.state, d.reason, d.release(NOW + TTL)) {
        (DraftState::Expired, Some(Reason::Timeout), Err(_)) => Outcome::Pass,
        other => Outcome::Fail(format!("{other:?}")),
    }
}

pub(crate) fn ca06_old_button_after_revise() -> Outcome {
    let mut d = draft(BODY, Required::Level(Level::A1));
    let old = d.clone();
    if let Err(e) = d.revise(
        1,
        revision("Bob thinks the plan is risky.", vec![]),
        NOW + 1,
    ) {
        return Outcome::Fail(format!("setup: revise refused: {e:?}"));
    }
    d.evaluated(
        Required::Level(Level::A1),
        Channel::TelegramMiniApp,
        seed(2),
        NOW + 1,
        TTL,
    );
    let stale = DecisionAttempt {
        release_digest: d.current.release_digest,
        ..approve(&old, Channel::TelegramButton)
    };
    expect(d.decide(&stale, NOW + 2), |e| {
        *e == DecisionError::UnknownRequest
    })
}

pub(crate) fn ca07_revise_or_withdraw_after_approval() -> Outcome {
    let snap = draft(BODY, Required::Level(Level::A1));
    let mut d = snap.clone();
    if d.decide(&approve(&snap, Channel::TelegramButton), NOW + 1)
        .is_err()
    {
        return Outcome::Fail("setup: approval refused".into());
    }
    let mut w = d.clone();
    all([
        expect(d.revise(1, revision("other", vec![]), NOW + 2), |e| {
            matches!(e, DraftError::InvalidState(DraftState::Approved))
        }),
        expect(w.withdraw(NOW + 2), |e| {
            matches!(e, DraftError::InvalidState(_))
        }),
    ])
}

pub(crate) fn ca08_attachment_swap() -> Outcome {
    let meta = |b: u8| AttachmentMeta {
        name: "notes.md".into(),
        media_type: "text/markdown".into(),
        size: 3,
        sha256: Sha256([b; 32]),
    };
    let mut d = draft(BODY, Required::Level(Level::A2));
    d.current = revision(BODY, vec![meta(1)]);
    d.evaluated(
        Required::Level(Level::A2),
        Channel::TelegramMiniApp,
        seed(1),
        NOW,
        TTL,
    );
    let shown = d.clone();
    d.current = revision(BODY, vec![meta(2)]);
    let a = approve(&shown, Channel::TelegramMiniApp);
    expect(d.decide(&a, NOW + 1), |e| {
        *e == DecisionError::DigestMismatch
    })
}

pub(crate) fn ca09_miniapp_digest_mismatch() -> Outcome {
    let d = draft(BODY, Required::Level(Level::A2));
    let a = DecisionAttempt {
        release_digest: Sha256([0; 32]),
        ..approve(&d, Channel::TelegramMiniApp)
    };
    expect(d.clone().decide(&a, NOW + 1), |e| {
        *e == DecisionError::DigestMismatch
    })
}

pub(crate) fn ca10_double_press() -> Outcome {
    let snap = draft(BODY, Required::Level(Level::A1));
    let mut d = snap.clone();
    let a = approve(&snap, Channel::TelegramButton);
    if d.decide(&a, NOW + 1).is_err() {
        return Outcome::Fail("setup: first press refused".into());
    }
    expect(d.decide(&a, NOW + 1), |e| {
        *e == DecisionError::UnknownRequest
    })
}

pub(crate) fn ca13_press_after_ttl() -> Outcome {
    let d = draft(BODY, Required::Level(Level::A1));
    let a = approve(&d, Channel::TelegramButton);
    expect(d.clone().decide(&a, NOW + TTL), |e| {
        *e == DecisionError::Expired
    })
}

pub(crate) fn ca15_non_approver() -> Outcome {
    let d = draft(BODY, Required::Level(Level::A1));
    let a = DecisionAttempt {
        approver: false,
        ..approve(&d, Channel::TelegramButton)
    };
    expect(d.clone().decide(&a, NOW + 1), |e| {
        *e == DecisionError::NotApprover
    })
}

pub(crate) fn ca21_level_without_channel() -> Outcome {
    let d = draft(BODY, Required::Level(Level::A2Plus));
    match (d.state, d.reason, d.request) {
        (DraftState::Blocked, Some(Reason::Policy), None) => Outcome::Pass,
        other => Outcome::Fail(format!("{other:?}")),
    }
}

pub(crate) fn ca39_cross_tenant_decision() -> Outcome {
    let d = draft(BODY, Required::Level(Level::A1));
    let other = tenant(3);
    let a = DecisionAttempt {
        tenant: &other,
        ..approve(&d, Channel::TelegramButton)
    };
    expect(d.clone().decide(&a, NOW + 1), |e| {
        *e == DecisionError::UnknownRequest
    })
}

pub(crate) fn ca47_weaker_channel() -> Outcome {
    let d = draft(BODY, Required::Level(Level::A2));
    let a = approve(&d, Channel::TelegramButton);
    expect(d.clone().decide(&a, NOW + 1), |e| {
        *e == DecisionError::ChannelTooWeak
    })
}
