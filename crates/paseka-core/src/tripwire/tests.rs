use paseka_proto::draft::DraftState;

use super::*;
use crate::channel::Selection;
use crate::open::{OpenBook, OpenDenied};
use crate::risk::{self, OwnerRules, Required};
use crate::testkit::{
    address, awaiting, cand, draft_id, free, mvp_channels, peer, seed, t1, tenant, thread, tpl,
};

const CANARY: &str = "PASEKA-CANARY-7f3a9c";
const TTL: u64 = 100;

fn rules() -> OwnerRules {
    let mut r = OwnerRules::default();
    r.add_canary(CanaryId(4), CANARY).unwrap();
    r
}

fn window(i: u64) -> McpWindow {
    McpWindow {
        from: 100 * i,
        until: 100 * i + 30,
    }
}

/// Tenant `t`'s draft `d` with `body`, evaluated against [`rules`] at `now`.
fn evaluated(t: u8, d: u8, body: &str, now: UnixSecs) -> (Draft, Assessment) {
    let a = risk::assess(&rules(), &free(body));
    let draft = awaiting(t, d, body, now, now + 10_000, a.required, now);
    (draft, a)
}

fn hit(book: &mut TripwireBook, t: u8, d: u8, now: UnixSecs) -> Option<Notice> {
    let (draft, a) = evaluated(t, d, &format!("here it is {CANARY}"), now);
    assert_eq!(draft.state, DraftState::Blocked);
    book.canary_hit(&draft, &a, window(u64::from(d)), now)
}

fn attempt<'a>(t: &'a TenantId, req: &'a ClearRequest, channel: Channel) -> ClearAttempt<'a> {
    ClearAttempt {
        tenant: t,
        request_id: &req.request_id,
        nonce: &req.nonce,
        channel,
        approver: true,
    }
}

#[test]
fn a_canary_hit_blocks_the_draft_and_enters_with_the_trigger() {
    let mut book = TripwireBook::default();
    let notice = hit(&mut book, 1, 1, 100).unwrap();
    let trigger = Trigger {
        peer: peer("bob"),
        draft: draft_id(1),
        revision: 1,
        canaries: vec![CanaryId(4)],
        journal: window(1),
        at: 100,
    };
    assert_eq!(
        notice,
        Notice {
            tenant: tenant(1),
            trigger: trigger.clone(),
            alarm: Alarm::Entered,
        }
    );
    assert_eq!(
        book.active(&tenant(1)),
        Some(&Active {
            triggers: vec![trigger],
            clear: None,
        })
    );
    assert!(book.in_effect(&tenant(1)));
}

#[test]
fn the_notice_holds_neither_the_canary_marker_nor_the_body() {
    let mut book = TripwireBook::default();
    let shown = format!("{:?}", hit(&mut book, 1, 1, 100).unwrap()).to_lowercase();
    for secret in ["7f3a9c", "here it is"] {
        assert!(!shown.contains(secret), "{shown}");
    }
}

#[test]
fn an_assessment_without_a_canary_changes_nothing() {
    let mut book = TripwireBook::default();
    let (draft, a) = evaluated(1, 1, "sounds good", 100);
    assert_eq!(book.canary_hit(&draft, &a, window(1), 100), None);
    assert!(!book.in_effect(&tenant(1)));
}

#[test]
fn a_second_hit_keeps_the_first_trigger_adds_its_own_and_revokes_the_clear_request() {
    let mut book = TripwireBook::default();
    hit(&mut book, 1, 1, 100);
    let req = book.request_clear(&tenant(1), seed(9), 110, TTL).unwrap();
    assert_eq!(hit(&mut book, 1, 2, 120).unwrap().alarm, Alarm::Added);
    let active = book.active(&tenant(1)).unwrap();
    let drafts: Vec<(&DraftId, UnixSecs)> =
        active.triggers.iter().map(|t| (&t.draft, t.at)).collect();
    assert_eq!(drafts, vec![(&draft_id(1), 100), (&draft_id(2), 120)]);
    assert_eq!(active.clear, None);
    let t = tenant(1);
    assert_eq!(
        book.clear(&attempt(&t, &req, Channel::TelegramMiniAppPin), 121),
        Err(ClearError::UnknownRequest)
    );
    assert!(book.in_effect(&t));
}

#[test]
fn only_a_pin_decision_on_the_live_clear_request_clears() {
    let t = tenant(1);
    let other = tenant(2);
    let mut book = TripwireBook::default();
    hit(&mut book, 1, 1, 100);
    let req = book.request_clear(&t, seed(9), 110, TTL).unwrap();
    let pin = attempt(&t, &req, Channel::TelegramMiniAppPin);
    let wrong_id = crate::testkit::request_id(8);
    let wrong_nonce = crate::testkit::nonce(8);
    let refused: [(ClearAttempt<'_>, UnixSecs, ClearError); 8] = [
        (
            attempt(&t, &req, Channel::TelegramButton),
            111,
            ClearError::ChannelTooWeak,
        ),
        (
            attempt(&t, &req, Channel::TelegramMiniApp),
            111,
            ClearError::ChannelTooWeak,
        ),
        (
            attempt(&t, &req, Channel::OpenMandate),
            111,
            ClearError::ChannelTooWeak,
        ),
        (
            ClearAttempt {
                request_id: &wrong_id,
                ..pin
            },
            111,
            ClearError::UnknownRequest,
        ),
        (
            ClearAttempt {
                nonce: &wrong_nonce,
                ..pin
            },
            111,
            ClearError::NonceMismatch,
        ),
        (pin, 110 + TTL, ClearError::Expired),
        (
            ClearAttempt {
                approver: false,
                ..pin
            },
            111,
            ClearError::NotApprover,
        ),
        (
            ClearAttempt {
                tenant: &other,
                ..pin
            },
            111,
            ClearError::NotActive,
        ),
    ];
    for (a, now, want) in refused {
        assert_eq!(book.clear(&a, now), Err(want), "{a:?} at {now}");
        assert!(book.in_effect(&t), "{a:?}");
        assert_eq!(book.active(&t).unwrap().clear.as_ref(), Some(&req));
    }
    let cleared = book.clear(&pin, 111).unwrap();
    assert_eq!(cleared.len(), 1);
    assert!(!book.in_effect(&t));
    assert_eq!(book.clear(&pin, 112), Err(ClearError::NotActive));
}

#[test]
fn a_clear_request_needs_active_tripwire_mode() {
    let mut book = TripwireBook::default();
    assert_eq!(
        book.request_clear(&tenant(1), seed(9), 100, TTL),
        Err(ClearError::NotActive)
    );
}

#[test]
fn full_alarm_raises_every_draft_to_the_pin_channel_and_stops_open_mandates() {
    let mut book = TripwireBook::default();
    let (m, to, tp, th) = (t1(1), address(2), tpl("availability"), thread(1));
    let mut open = OpenBook::default();
    open.present(&m, 5).unwrap();
    open.activate(&m).unwrap();
    hit(&mut book, 1, 1, 10);
    let on = book.in_effect(&tenant(1));
    assert_eq!(
        open.matches(&m, &cand(&to, &tp, &th), on, 20),
        Err(OpenDenied::Inactive)
    );
    let cases: [(&str, bool, Required); 4] = [
        ("sounds good", false, Required::Level(Level::A2Plus)),
        ("sounds good", true, Required::Level(Level::A2Plus)),
        (
            "see https://example.org/x",
            false,
            Required::Level(Level::A2Plus),
        ),
        (CANARY, false, Required::Block),
    ];
    for (text, open_mandate, want) in cases {
        let a = risk::assess(
            &rules(),
            &risk::Draft {
                tripwire: on,
                open_mandate,
                ..free(text)
            },
        );
        assert_eq!(a.required, want, "{text}");
    }
    assert_eq!(
        mvp_channels().select(TRIPWIRE_LEVEL),
        Selection::Satisfies(Channel::TelegramMiniAppPin)
    );
}

#[test]
fn draft_block_only_blocks_the_draft_and_leaves_the_rest_alone() {
    let mut book = TripwireBook::default();
    book.set_mode(
        &tenant(1),
        TripwireMode::DraftBlockOnly,
        Channel::TelegramMiniApp,
    )
    .unwrap();
    let (m, to, tp, th) = (t1(1), address(2), tpl("availability"), thread(1));
    let mut open = OpenBook::default();
    open.present(&m, 5).unwrap();
    open.activate(&m).unwrap();
    assert_eq!(hit(&mut book, 1, 1, 10).unwrap().alarm, Alarm::DraftOnly);
    let on = book.in_effect(&tenant(1));
    assert!(!on);
    assert_eq!(book.active(&tenant(1)), None);
    assert_eq!(open.matches(&m, &cand(&to, &tp, &th), on, 20), Ok(()));
    assert_eq!(
        risk::assess(
            &rules(),
            &risk::Draft {
                tripwire: on,
                ..free("sounds good")
            }
        )
        .required,
        Required::Level(Level::A1)
    );
}

#[test]
fn the_mode_defaults_to_full_alarm_and_changes_only_by_consent_while_inactive() {
    let t = tenant(1);
    let mut book = TripwireBook::default();
    assert_eq!(book.mode(&t), TripwireMode::FullAlarm);
    for channel in [Channel::OpenMandate, Channel::TelegramButton] {
        assert_eq!(
            book.set_mode(&t, TripwireMode::DraftBlockOnly, channel),
            Err(ModeError::ChannelTooWeak)
        );
    }
    assert_eq!(book.mode(&t), TripwireMode::FullAlarm);
    hit(&mut book, 1, 1, 100);
    for channel in [Channel::TelegramMiniApp, Channel::TelegramMiniAppPin] {
        assert_eq!(
            book.set_mode(&t, TripwireMode::DraftBlockOnly, channel),
            Err(ModeError::TripwireActive)
        );
    }
    assert!(book.in_effect(&t));
    let req = book.request_clear(&t, seed(9), 110, TTL).unwrap();
    book.clear(&attempt(&t, &req, Channel::TelegramMiniAppPin), 111)
        .unwrap();
    assert_eq!(
        book.set_mode(&t, TripwireMode::DraftBlockOnly, Channel::TelegramMiniApp),
        Ok(())
    );
    assert_eq!(book.mode(&t), TripwireMode::DraftBlockOnly);
}

#[test]
fn one_tenants_tripwire_leaves_another_unaffected() {
    let mut book = TripwireBook::default();
    hit(&mut book, 1, 1, 100);
    assert!(book.in_effect(&tenant(1)));
    assert!(!book.in_effect(&tenant(2)));
    assert_eq!(
        book.request_clear(&tenant(2), seed(9), 110, TTL),
        Err(ClearError::NotActive)
    );
}
