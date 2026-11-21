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

/// One `thread_trust` question; each table case changes one input of the active base case.
#[derive(Clone)]
struct Ask {
    book: OpenBook,
    m: OpenMandate,
    tenant: TenantId,
    peer: Address,
    thread: ThreadId,
    tripwire: bool,
    now: UnixSecs,
}

type Change = fn(&mut Ask);

impl Ask {
    fn answer(&self) -> ThreadTrust {
        let ms = std::slice::from_ref(&self.m);
        thread_trust(
            &self.book,
            ms,
            &self.tenant,
            &self.peer,
            &self.thread,
            self.tripwire,
            self.now,
        )
    }
}

#[test]
fn thread_trust_is_active_only_for_a_live_conversation_mandate_on_that_thread_and_peer() {
    let m = conversation(1);
    let mut book = OpenBook::default();
    book.present(&m, 0).unwrap();
    book.activate(&m).unwrap();
    let base = Ask {
        book,
        m,
        tenant: tenant(1),
        peer: address(2),
        thread: thread(1),
        tripwire: false,
        now: 600,
    };
    let end = CONVERSATION_TTL_DEFAULT;
    let cases: [(&str, Change, Option<u64>); 10] = [
        ("active", |_| {}, Some(end - 600)),
        (
            "last second",
            |a| a.now = CONVERSATION_TTL_DEFAULT - 1,
            Some(1),
        ),
        ("another thread", |a| a.thread = thread(2), None),
        ("another peer", |a| a.peer = address(3), None),
        ("another tenant", |a| a.tenant = tenant(2), None),
        ("expired", |a| a.now = CONVERSATION_TTL_DEFAULT, None),
        ("revoked", |a| a.book.revoke(&a.m.tenant, &a.m.jti), None),
        ("tripwire", |a| a.tripwire = true, None),
        (
            "not signed yet",
            |a| {
                a.book = OpenBook::default();
                a.book.present(&a.m, 0).unwrap();
            },
            None,
        ),
        (
            "no message left",
            |a| {
                a.m.constraints.rate.max_messages = Some(1);
                a.book.consume(&a.m, 10);
            },
            None,
        ),
    ];
    for (name, change, left) in cases {
        let mut ask = base.clone();
        change(&mut ask);
        let want = ThreadTrust {
            active: left.is_some(),
            ends_at: left.map(|_| end),
            seconds_left: left,
            new_thread_needs_owner: true,
        };
        assert_eq!(ask.answer(), want, "{name}");
    }
}
