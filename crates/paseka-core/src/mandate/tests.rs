use ed25519_dalek::SigningKey;
use paseka_proto::evidence::{Channel, Proof};
use paseka_proto::mandate::{Constraints, Rate};

use super::*;
use crate::testkit::{key, nonce, peer, tenant};
use crate::token::{Approver, kid_of};

const NOW: UnixSecs = 1_000_000;

struct Fx {
    ring: ApproverRing,
    nonces: NonceBook,
    approver: SigningKey,
}

fn fx() -> Fx {
    let approver = key(9);
    let mut ring = ApproverRing::default();
    ring.insert(Approver {
        tenant: tenant("alice"),
        max_level: Level::A2,
        key: approver.verifying_key(),
    });
    let mut nonces = NonceBook::default();
    let binding = Binding {
        to: peer("bob"),
        content_sha256: content_sha256(TEXT),
    };
    nonces.issue(&tenant("alice"), nonce(1), binding, NOW + 60);
    Fx {
        ring,
        nonces,
        approver,
    }
}

const TEXT: &str = "Bob, I think X is worth trying.";

fn proof(channel: Channel) -> Proof {
    Proof {
        channel,
        evidence: serde_json::Map::new(),
    }
}

fn closed() -> ClosedMandate {
    ClosedMandate {
        tenant: tenant("alice"),
        to: peer("bob"),
        content_sha256: content_sha256(TEXT),
        attachments: vec![],
        level: Level::A2,
        proof: proof(Channel::TelegramMiniApp),
        nonce: nonce(1),
        exp: NOW + 60,
    }
}

fn sign(k: &SigningKey, m: &Mandate) -> String {
    token::sign(
        k,
        &kid_of(&k.verifying_key()),
        TYP_MANDATE,
        &serde_json::to_vec(m).unwrap(),
    )
}

fn out<'a>(tenant: &'a TenantId, to: &'a PeerId, text: &'a str) -> Outgoing<'a> {
    Outgoing {
        tenant,
        to,
        text,
        attachments: &[],
    }
}

fn verify(
    f: &mut Fx,
    m: &ClosedMandate,
    text: &str,
    required: Level,
    now: UnixSecs,
) -> Result<ClosedMandate, MandateError> {
    let t = sign(&f.approver, &Mandate::Closed(m.clone()));
    let (alice, bob) = (tenant("alice"), peer("bob"));
    verify_closed(
        &f.ring,
        &mut f.nonces,
        &t,
        out(&alice, &bob, text),
        required,
        now,
    )
}

#[test]
fn valid_closed_mandate_releases_once() {
    let mut f = fx();
    assert!(verify(&mut f, &closed(), TEXT, Level::A2, NOW).is_ok());
    assert_eq!(
        verify(&mut f, &closed(), TEXT, Level::A2, NOW + 1),
        Err(MandateError::Nonce(NonceError::Used))
    );
}

#[test]
fn closed_mandate_is_bound_to_exact_text_recipient_and_attachments() {
    let mut f = fx();
    assert_eq!(
        verify(
            &mut f,
            &closed(),
            "Bob, I think X is worth trying!",
            Level::A2,
            NOW
        ),
        Err(MandateError::HashMismatch)
    );
    let t = sign(&f.approver, &Mandate::Closed(closed()));
    let (alice, carol) = (tenant("alice"), peer("carol"));
    assert_eq!(
        verify_closed(
            &f.ring,
            &mut f.nonces,
            &t,
            out(&alice, &carol, TEXT),
            Level::A2,
            NOW
        ),
        Err(MandateError::WrongRecipient)
    );
    let att = [AttachmentRef {
        name: "a.pdf".into(),
        media_type: "application/pdf".into(),
        sha256: content_sha256("pdf"),
        size: 3,
    }];
    let bob = peer("bob");
    let o = Outgoing {
        tenant: &alice,
        to: &bob,
        text: TEXT,
        attachments: &att,
    };
    assert_eq!(
        verify_closed(&f.ring, &mut f.nonces, &t, o, Level::A2, NOW),
        Err(MandateError::AttachmentsMismatch)
    );
    assert!(
        verify(&mut f, &closed(), TEXT, Level::A2, NOW).is_ok(),
        "rejections must not burn the nonce"
    );
}

#[test]
fn forged_tampered_and_foreign_tenant_mandates_are_refused() {
    let mut f = fx();
    let forged = sign(&key(66), &Mandate::Closed(closed()));
    let (alice, bob) = (tenant("alice"), peer("bob"));
    assert_eq!(
        verify_closed(
            &f.ring,
            &mut f.nonces,
            &forged,
            out(&alice, &bob, TEXT),
            Level::A1,
            NOW
        ),
        Err(MandateError::Token(TokenError::UnknownKey))
    );
    let good = sign(&f.approver, &Mandate::Closed(closed()));
    let mut parts: Vec<&str> = good.split('.').collect();
    let mut m = closed();
    m.to = peer("carol");
    let swapped = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        serde_json::to_vec(&Mandate::Closed(m)).unwrap(),
    );
    parts[1] = &swapped;
    assert_eq!(
        verify_closed(
            &f.ring,
            &mut f.nonces,
            &parts.join("."),
            out(&alice, &peer("carol"), TEXT),
            Level::A1,
            NOW
        ),
        Err(MandateError::Token(TokenError::BadSignature))
    );
    let mut other = closed();
    other.tenant = tenant("carol");
    assert_eq!(
        verify(&mut f, &other, TEXT, Level::A1, NOW),
        Err(MandateError::WrongTenant)
    );
}

#[test]
fn expiry_and_lifetime_are_enforced() {
    let mut f = fx();
    assert_eq!(
        verify(&mut f, &closed(), TEXT, Level::A2, NOW + 60),
        Err(MandateError::Expired)
    );
    let mut long = closed();
    long.exp = NOW + MAX_CLOSED_TTL_SECS + 1;
    assert_eq!(
        verify(&mut f, &long, TEXT, Level::A2, NOW),
        Err(MandateError::TtlTooLong)
    );
}

#[test]
fn level_must_meet_requirement_channel_and_approver() {
    let mut f = fx();
    assert_eq!(
        verify(&mut f, &closed(), TEXT, Level::A2Plus, NOW),
        Err(MandateError::LevelTooLow)
    );
    let mut button = closed();
    button.proof = proof(Channel::TelegramButton);
    assert_eq!(
        verify(&mut f, &button, TEXT, Level::A2, NOW),
        Err(MandateError::ChannelCannotAttest)
    );
    let mut unknown = closed();
    unknown.proof = proof(Channel::Unknown);
    assert_eq!(
        verify(&mut f, &unknown, TEXT, Level::A1, NOW),
        Err(MandateError::ChannelCannotAttest)
    );
    let mut passkey = closed();
    passkey.level = Level::A3;
    passkey.proof = proof(Channel::Passkey);
    assert_eq!(
        verify(&mut f, &passkey, TEXT, Level::A3, NOW),
        Err(MandateError::ApproverCannotAttest)
    );
}

#[test]
fn unissued_nonce_is_refused() {
    let mut f = fx();
    let mut m = closed();
    m.nonce = nonce(2);
    assert_eq!(
        verify(&mut f, &m, TEXT, Level::A2, NOW),
        Err(MandateError::Nonce(NonceError::Unknown))
    );
}

fn open(templates: &[&str]) -> OpenMandate {
    OpenMandate {
        tenant: tenant("alice"),
        to: peer("bob"),
        constraints: Constraints {
            templates: templates.iter().map(|s| (*s).to_owned()).collect(),
            max_len: 200,
            attachments: false,
            private_sources: false,
            rate: Rate {
                max_messages: 2,
                per_secs: 600,
            },
            topics: vec![],
        },
        nbf: NOW,
        exp: NOW + 1800,
        signed_at_level: Level::A1,
        proof: proof(Channel::TelegramButton),
        nonce: nonce(5),
    }
}

#[test]
fn open_mandate_needs_a_human_signature_and_a_valid_window() {
    let f = fx();
    let (alice, bob) = (tenant("alice"), peer("bob"));
    let t = sign(&f.approver, &Mandate::Open(open(&[])));
    assert!(verify_open(&f.ring, &t, &alice, &bob, NOW).is_ok());
    assert_eq!(
        verify_open(&f.ring, &t, &alice, &bob, NOW + 1800),
        Err(MandateError::Expired)
    );
    assert_eq!(
        verify_open(&f.ring, &t, &alice, &bob, NOW - 1),
        Err(MandateError::NotYetValid)
    );
    let mut policy = open(&[]);
    policy.signed_at_level = Level::A0;
    policy.proof = proof(Channel::Policy);
    let t = sign(&f.approver, &Mandate::Open(policy));
    assert_eq!(
        verify_open(&f.ring, &t, &alice, &bob, NOW),
        Err(MandateError::LevelTooLow)
    );
    let t = sign(&f.approver, &Mandate::Closed(closed()));
    assert_eq!(
        verify_open(&f.ring, &t, &alice, &bob, NOW),
        Err(MandateError::WrongKind)
    );
}

#[test]
fn open_mandate_admits_only_within_constraints_and_rate() {
    let m = open(&["I am free on {day} after {time}."]);
    let (alice, bob) = (tenant("alice"), peer("bob"));
    let mut ledger = RateLedger::default();
    let ok = "I am free on Friday after 18:00.";
    assert_eq!(
        admit_open(&m, out(&alice, &bob, ok), false, &mut ledger, NOW),
        Ok(())
    );
    let smuggle = "I am free on https://example.org/x after 18:00.";
    assert_eq!(
        admit_open(&m, out(&alice, &bob, smuggle), false, &mut ledger, NOW),
        Err(OpenDenied::NoTemplate)
    );
    assert_eq!(
        admit_open(&m, out(&alice, &bob, "Free text."), false, &mut ledger, NOW),
        Err(OpenDenied::NoTemplate)
    );
    assert_eq!(
        admit_open(&m, out(&alice, &bob, ok), true, &mut ledger, NOW),
        Err(OpenDenied::PrivateSources)
    );
    assert_eq!(
        admit_open(&m, out(&alice, &bob, ok), false, &mut ledger, NOW + 1),
        Ok(())
    );
    assert_eq!(
        admit_open(&m, out(&alice, &bob, ok), false, &mut ledger, NOW + 2),
        Err(OpenDenied::Rate)
    );
    assert_eq!(
        admit_open(&m, out(&alice, &bob, ok), false, &mut ledger, NOW + 600),
        Ok(())
    );
    let long = "a".repeat(201);
    assert_eq!(
        admit_open(
            &open(&[]),
            out(&alice, &bob, &long),
            false,
            &mut ledger,
            NOW
        ),
        Err(OpenDenied::TooLong)
    );
}

#[test]
fn template_parsing_rejects_ambiguous_templates() {
    assert!(Template::parse("{a}{b}").is_none());
    assert!(Template::parse("a {b").is_none());
    assert!(Template::parse("a }b").is_none());
    let t = Template::parse("{greeting}, Alice").unwrap();
    assert!(t.matches("Hi, Alice"));
    assert!(!t.matches("Hi, Alice!"));
    assert!(!t.matches(", Alice"));
}

#[test]
fn new_open_mandate_waits_until_the_previous_is_refused_or_expired() {
    let mut s = OpenSlots::default();
    let (alice, bob) = (tenant("alice"), peer("bob"));
    s.present(&alice, &bob, nonce(1), NOW + 100, NOW).unwrap();
    assert_eq!(
        s.present(&alice, &bob, nonce(2), NOW + 100, NOW),
        Err(SlotError::PreviousNotRefused)
    );
    s.activate(&alice, &bob, &nonce(1)).unwrap();
    assert!(s.is_active(&alice, &bob, &nonce(1), NOW));
    assert_eq!(
        s.present(&alice, &bob, nonce(2), NOW + 100, NOW),
        Err(SlotError::PreviousNotRefused)
    );
    s.refuse(&alice, &bob, &nonce(1)).unwrap();
    assert!(!s.is_active(&alice, &bob, &nonce(1), NOW));
    s.present(&alice, &bob, nonce(2), NOW + 100, NOW).unwrap();
    assert!(
        s.present(&alice, &bob, nonce(3), NOW + 200, NOW + 100)
            .is_ok(),
        "expired previous"
    );
    assert!(
        s.present(&tenant("carol"), &bob, nonce(4), NOW + 100, NOW)
            .is_ok()
    );
}
