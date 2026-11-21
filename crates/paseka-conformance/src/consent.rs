//! Attacks on the consent path: drafts, approval requests and decisions (SP-2 to SP-7, SP-16,
//! SP-19).

use paseka_core::channel::Selection;
use paseka_core::draft::{
    DRAFTS_PER_PEER_PER_HOUR, DecisionAttempt, DecisionError, DraftError, DraftLimit,
    PENDING_DRAFTS_PER_TENANT, admit,
};
use paseka_core::risk::Required;
use paseka_proto::draft::{DraftState, Reason};
use paseka_proto::evidence::Channel;
use paseka_proto::mandate::AttachmentMeta;
use paseka_proto::{Level, PeerHandle, Sha256};

use crate::world::{BODY, NOW, TTL, approve, draft, mvp_channels, revision, seed, tenant};
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
        &mvp_channels(),
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
        &mvp_channels(),
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

pub(crate) fn ca21_level_above_every_channel() -> Outcome {
    let d = draft(BODY, Required::Level(Level::A3));
    let Some(req) = d.request.clone() else {
        return Outcome::Fail(format!("not sent to the owner: {:?}", (d.state, d.reason)));
    };
    if req.level != Level::A3
        || req.selection != Selection::AboveAvailable(Channel::TelegramMiniAppPin)
    {
        return Outcome::Fail(format!("request {:?} via {:?}", req.level, req.selection));
    }
    let strongest = d
        .clone()
        .decide(&approve(&d, Channel::TelegramMiniAppPin), NOW + 1);
    all([
        expect(
            d.clone()
                .decide(&approve(&d, Channel::TelegramMiniApp), NOW + 1),
            |e| *e == DecisionError::ChannelTooWeak,
        ),
        match strongest {
            Ok(Some(a)) if (a.level, a.required) == (Level::A2Plus, Level::A3) => Outcome::Pass,
            other => Outcome::Fail(format!("strongest channel: {other:?}")),
        },
    ])
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

/// 100 proposals within a minute, to one peer and spread over two: the peer limit refuses the
/// first, the pending limit the second, and every refusal is `rate_limited`.
pub(crate) fn ca43_draft_flood() -> Outcome {
    let bob = PeerHandle::new("bob").expect("fixture handle");
    let carol = PeerHandle::new("carol").expect("fixture handle");
    let floods = [
        (
            vec![&bob],
            DRAFTS_PER_PEER_PER_HOUR,
            DraftLimit::PerPeerHour,
        ),
        (
            vec![&bob, &carol],
            PENDING_DRAFTS_PER_TENANT,
            DraftLimit::PendingPerTenant,
        ),
    ];
    all(floods.into_iter().map(|(peers, limit, refusal)| {
        let mut created = Vec::new();
        for (i, at) in (0..100u64).enumerate() {
            let to = peers[i % peers.len()];
            let now = NOW + at * 3 / 5;
            match admit(&created, &tenant(1), to, now) {
                Ok(()) => {
                    let mut d = draft(BODY, Required::Level(Level::A1));
                    d.to = to.clone();
                    d.created_at = now;
                    created.push(d);
                }
                Err(DraftError::RateLimited(r)) if r == refusal && created.len() == limit => {}
                Err(e) => {
                    return Outcome::Fail(format!("proposal {i}: {e:?} after {}", created.len()));
                }
            }
        }
        if created.len() == limit {
            Outcome::Pass
        } else {
            Outcome::Fail(format!("{} of 100 proposals admitted", created.len()))
        }
    }))
}
