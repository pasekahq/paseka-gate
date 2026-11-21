use paseka_proto::draft::DraftState;
use paseka_proto::mandate::Rate;

use super::*;
use crate::draft::{DraftError, DraftLimit, admit};
use crate::testkit::{address, cand, conversation, drafts, peer, t1, tenant, thread, tpl};

#[test]
fn shape_rules_reject_weak_signers_and_missing_constraints() {
    assert_eq!(check_shape(&t1(1)), Ok(()));
    let mut m = t1(1);
    m.signed_at_level = Level::A1;
    assert!(check_shape(&m).is_err());
    let mut m = t1(1);
    m.proof.channel = Channel::TelegramButton;
    assert!(check_shape(&m).is_err());
    let mut m = t1(1);
    m.constraints.templates.clear();
    assert!(check_shape(&m).is_err());
    let mut m = t1(1);
    m.exp = 31 * DAY;
    assert!(check_shape(&m).is_err());
}

#[test]
fn matching_needs_activation_and_stops_at_the_rate() {
    let (m, to, t, th) = (t1(1), address(2), tpl("availability"), thread(1));
    let mut book = OpenBook::default();
    assert_eq!(
        book.matches(&m, &cand(&to, &t, &th), false, 10),
        Err(OpenDenied::Inactive)
    );
    book.present(&m, 5).unwrap();
    book.activate(&m).unwrap();
    assert_eq!(book.matches(&m, &cand(&to, &t, &th), false, 10), Ok(()));
    assert_eq!(
        book.matches(&m, &cand(&to, &t, &th), true, 10),
        Err(OpenDenied::Inactive)
    );
    let other = tpl("other");
    assert_eq!(
        book.matches(&m, &cand(&to, &other, &th), false, 10),
        Err(OpenDenied::Kind)
    );
    book.consume(&m, 10);
    book.consume(&m, 11);
    assert_eq!(
        book.matches(&m, &cand(&to, &t, &th), false, 12),
        Err(OpenDenied::Rate)
    );
}

#[test]
fn revocation_takes_effect_at_once() {
    let (m, to, t, th) = (t1(1), address(2), tpl("availability"), thread(1));
    let mut book = OpenBook::default();
    book.present(&m, 5).unwrap();
    book.activate(&m).unwrap();
    book.revoke(&m.tenant, &m.jti);
    assert_eq!(
        book.matches(&m, &cand(&to, &t, &th), false, 10),
        Err(OpenDenied::Inactive)
    );
}

#[test]
fn a_second_mandate_waits_until_the_pending_one_is_refused() {
    let mut book = OpenBook::default();
    book.present(&t1(1), 5).unwrap();
    assert_eq!(book.present(&t1(2), 6), Err(SlotError::PreviousPending));
    book.refuse(&t1(1));
    assert_eq!(book.present(&t1(2), 7), Ok(()));
}

#[test]
fn conversation_trust_needs_a_thread_but_no_rate_while_other_trusts_keep_theirs() {
    let lasting = |secs| OpenMandate {
        exp: secs,
        ..conversation(1)
    };
    let mut no_thread = conversation(1);
    no_thread.constraints.thread = None;
    let mut t1_no_rate = t1(1);
    t1_no_rate.constraints.rate = Rate::default();
    let cases = [
        (lasting(CONVERSATION_TTL_DEFAULT), true),
        (lasting(max_lifetime(OpenTrust::Conversation)), true),
        (lasting(max_lifetime(OpenTrust::Conversation) + 1), false),
        (no_thread, false),
        (t1_no_rate, false),
    ];
    for (i, (m, ok)) in cases.into_iter().enumerate() {
        assert_eq!(check_shape(&m).is_ok(), ok, "case {i}");
    }
}

#[test]
fn conversation_trust_has_no_message_limit_but_the_peer_limit_still_applies() {
    let (m, to, th) = (conversation(1), address(2), thread(1));
    let c = Candidate {
        to: &to,
        kind: DraftKind::FreeText,
        template: None,
        shelf: None,
        thread: &th,
        body_len: 10,
        foreign_attachments: false,
        private_sources: false,
    };
    let mut book = OpenBook::default();
    book.present(&m, 0).unwrap();
    book.activate(&m).unwrap();
    for now in 0..100 {
        book.consume(&m, now);
    }
    assert_eq!(book.matches(&m, &c, false, 100), Ok(()));
    let released = drafts(1, 30, "bob", 0, DraftState::Released);
    assert_eq!(
        admit(&released, &tenant(1), &peer("bob"), 100),
        Err(DraftError::RateLimited(DraftLimit::PerPeerHour))
    );
}
