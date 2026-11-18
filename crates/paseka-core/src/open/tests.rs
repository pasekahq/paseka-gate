use paseka_proto::mandate::{Constraints, OpenKind, OpenProof, Rate};
use paseka_proto::{Sha256, V1};

use super::*;
use crate::testkit::{kid, tenant, thread};

fn tpl(s: &str) -> TemplateId {
    TemplateId::new(s).unwrap()
}

fn jti(i: u8) -> MandateId {
    MandateId::new(format!("md_01JD{i:0>22}")).unwrap()
}

fn t1(i: u8) -> OpenMandate {
    OpenMandate {
        v: V1,
        kind: OpenKind::Open,
        iss: kid(1),
        tenant: tenant(1),
        to: kid(2),
        jti: jti(i),
        iat: 0,
        nbf: 0,
        exp: 1000,
        trust: OpenTrust::T1,
        signed_at_level: Level::A2,
        constraints: Constraints {
            templates: vec![tpl("availability")],
            max_len: Some(200),
            attachments: None,
            private_sources: None,
            rate: Rate {
                max_messages: Some(2),
                per_hour: None,
                per_day: None,
            },
            topics: vec![],
            shelves: vec![],
            thread: None,
        },
        proof: OpenProof {
            channel: Channel::TelegramMiniApp,
            approved_at: 0,
            evidence_sha256: Sha256([0; 32]),
        },
    }
}

fn cand<'a>(to: &'a KeyId, t: &'a TemplateId, th: &'a ThreadId) -> Candidate<'a> {
    Candidate {
        to,
        kind: DraftKind::Template,
        template: Some(t),
        shelf: None,
        thread: th,
        body_len: 10,
        foreign_attachments: false,
        private_sources: false,
    }
}

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
    let (m, to, t, th) = (t1(1), kid(2), tpl("availability"), thread(1));
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
    let (m, to, t, th) = (t1(1), kid(2), tpl("availability"), thread(1));
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
