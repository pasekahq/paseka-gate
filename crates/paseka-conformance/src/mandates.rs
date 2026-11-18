//! Attacks on closed and open mandates.

use paseka_core::mandate::{
    self, MandateError, OpenDenied, OpenSlots, Outgoing, RateLedger, SlotError,
};
use paseka_core::nonce::NonceError;
use paseka_core::token::TokenError;
use paseka_proto::Level;
use paseka_proto::evidence::Channel;
use paseka_proto::mandate::{AttachmentRef, Constraints, Mandate, OpenMandate, Rate};

use crate::fixture::{Gate, NOW, TEXT, b64, closed, key, nonce, peer, proof, sign, tenant};
use crate::{Outcome, all, expect};

pub(crate) fn forged() -> Outcome {
    let mut g = Gate::new();
    let t = sign(&key(66), &Mandate::Closed(closed()));
    expect(g.release(&t, "bob", TEXT, &[], Level::A2, NOW), |e| {
        *e == MandateError::Token(TokenError::UnknownKey)
    })
}

pub(crate) fn tampered() -> Outcome {
    let mut g = Gate::new();
    let good = sign(&g.approver, &Mandate::Closed(closed()));
    let mut m = closed();
    m.level = Level::A3;
    let payload = b64(&serde_json::to_vec(&Mandate::Closed(m)).expect("serialises"));
    let parts: Vec<&str> = good.split('.').collect();
    let t = format!("{}.{payload}.{}", parts[0], parts[2]);
    expect(g.release(&t, "bob", TEXT, &[], Level::A2, NOW), |e| {
        *e == MandateError::Token(TokenError::BadSignature)
    })
}

pub(crate) fn alg_confusion() -> Outcome {
    let mut g = Gate::new();
    let payload = b64(&serde_json::to_vec(&Mandate::Closed(closed())).expect("serialises"));
    let kid = paseka_core::token::kid_of(&g.approver.verifying_key());
    let none =
        b64(format!(r#"{{"alg":"none","typ":"paseka-mandate+jwt","kid":"{kid}"}}"#).as_bytes());
    let eddsa =
        b64(format!(r#"{{"alg":"EdDSA","typ":"paseka-mandate+jwt","kid":"{kid}"}}"#).as_bytes());
    all([
        expect(
            g.release(
                &format!("{none}.{payload}."),
                "bob",
                TEXT,
                &[],
                Level::A2,
                NOW,
            ),
            |e| *e == MandateError::Token(TokenError::BadAlg),
        ),
        expect(
            g.release(
                &format!("{eddsa}.{payload}."),
                "bob",
                TEXT,
                &[],
                Level::A2,
                NOW,
            ),
            |e| *e == MandateError::Token(TokenError::BadSignature),
        ),
    ])
}

pub(crate) fn expired() -> Outcome {
    let mut g = Gate::new();
    let t = sign(&g.approver, &Mandate::Closed(closed()));
    expect(g.release(&t, "bob", TEXT, &[], Level::A2, NOW + 61), |e| {
        *e == MandateError::Expired
    })
}

pub(crate) fn overlong() -> Outcome {
    let mut g = Gate::new();
    let mut m = closed();
    m.exp = NOW + 24 * 3600;
    let t = sign(&g.approver, &Mandate::Closed(m));
    expect(g.release(&t, "bob", TEXT, &[], Level::A2, NOW), |e| {
        *e == MandateError::TtlTooLong
    })
}

pub(crate) fn replayed() -> Outcome {
    let mut g = Gate::new();
    let t = sign(&g.approver, &Mandate::Closed(closed()));
    if let Err(e) = g.release(&t, "bob", TEXT, &[], Level::A2, NOW) {
        return Outcome::Fail(format!("first, legitimate use refused: {e:?}"));
    }
    expect(g.release(&t, "bob", TEXT, &[], Level::A2, NOW + 1), |e| {
        *e == MandateError::Nonce(NonceError::Used)
    })
}

pub(crate) fn stale_nonce() -> Outcome {
    let mut g = Gate::new();
    let mut m = closed();
    m.nonce = nonce(99);
    let unissued = sign(&g.approver, &Mandate::Closed(m));
    let mut late = closed();
    late.exp = NOW + 100;
    let past_nonce = sign(&g.approver, &Mandate::Closed(late));
    all([
        expect(
            g.release(&unissued, "bob", TEXT, &[], Level::A2, NOW),
            |e| *e == MandateError::Nonce(NonceError::Unknown),
        ),
        expect(
            g.release(&past_nonce, "bob", TEXT, &[], Level::A2, NOW + 70),
            |e| *e == MandateError::Nonce(NonceError::Expired),
        ),
    ])
}

pub(crate) fn preview_swap() -> Outcome {
    let mut g = Gate::new();
    let t = sign(&g.approver, &Mandate::Closed(closed()));
    let swapped = "Alice thinks X is promising. Her card is 4111 1111 1111 1111.";
    expect(g.release(&t, "bob", swapped, &[], Level::A2, NOW), |e| {
        *e == MandateError::HashMismatch
    })
}

pub(crate) fn recipient_swap() -> Outcome {
    let mut g = Gate::new();
    let t = sign(&g.approver, &Mandate::Closed(closed()));
    expect(g.release(&t, "carol", TEXT, &[], Level::A2, NOW), |e| {
        *e == MandateError::WrongRecipient
    })
}

pub(crate) fn attachment_swap() -> Outcome {
    let mut g = Gate::new();
    let t = sign(&g.approver, &Mandate::Closed(closed()));
    let extra = [AttachmentRef {
        name: "notes.txt".into(),
        media_type: "text/plain".into(),
        sha256: paseka_core::hash::sha256(b"private notes"),
        size: 13,
    }];
    expect(g.release(&t, "bob", TEXT, &extra, Level::A2, NOW), |e| {
        *e == MandateError::AttachmentsMismatch
    })
}

pub(crate) fn cross_tenant() -> Outcome {
    let mut g = Gate::new();
    let t = sign(&key(42), &Mandate::Closed(closed()));
    expect(g.release(&t, "bob", TEXT, &[], Level::A2, NOW), |e| {
        *e == MandateError::WrongTenant
    })
}

pub(crate) fn level_downgrade() -> Outcome {
    let mut g = Gate::new();
    let mut m = closed();
    m.level = Level::A1;
    m.proof = proof(Channel::TelegramButton);
    let low = sign(&g.approver, &Mandate::Closed(m));
    let mut lie = closed();
    lie.proof = proof(Channel::TelegramButton);
    let claimed = sign(&g.approver, &Mandate::Closed(lie));
    all([
        expect(g.release(&low, "bob", TEXT, &[], Level::A2, NOW), |e| {
            *e == MandateError::LevelTooLow
        }),
        expect(g.release(&claimed, "bob", TEXT, &[], Level::A2, NOW), |e| {
            *e == MandateError::ChannelCannotAttest
        }),
    ])
}

pub(crate) fn unknown_channel() -> Outcome {
    let mut g = Gate::new();
    let mut v = serde_json::to_value(Mandate::Closed(closed())).expect("serialises");
    v["proof"]["channel"] = "carrier_pigeon".into();
    let payload = serde_json::to_vec(&v).expect("serialises");
    let t = paseka_core::token::sign(
        &g.approver,
        &paseka_core::token::kid_of(&g.approver.verifying_key()),
        paseka_proto::jws::TYP_MANDATE,
        &payload,
    );
    expect(g.release(&t, "bob", TEXT, &[], Level::A1, NOW), |e| {
        *e == MandateError::ChannelCannotAttest
    })
}

fn open_mandate() -> OpenMandate {
    OpenMandate {
        tenant: tenant("alice"),
        to: peer("bob"),
        constraints: Constraints {
            templates: vec!["Alice is free on {day} after {time}.".into()],
            max_len: 200,
            attachments: false,
            private_sources: false,
            rate: Rate {
                max_messages: 3,
                per_secs: 3600,
            },
            topics: vec![],
        },
        nbf: NOW,
        exp: NOW + 1800,
        signed_at_level: Level::A1,
        proof: proof(Channel::TelegramButton),
        nonce: nonce(7),
    }
}

pub(crate) fn open_by_policy() -> Outcome {
    let g = Gate::new();
    let mut m = open_mandate();
    m.signed_at_level = Level::A0;
    m.proof = proof(Channel::Policy);
    let t = sign(&g.approver, &Mandate::Open(m));
    expect(
        mandate::verify_open(&g.ring, &t, &tenant("alice"), &peer("bob"), NOW),
        |e| *e == MandateError::LevelTooLow,
    )
}

pub(crate) fn open_slot_smuggle() -> Outcome {
    let m = open_mandate();
    let (alice, bob) = (tenant("alice"), peer("bob"));
    let mut ledger = RateLedger::default();
    let texts = [
        "Alice is free on https://example.org/?q=diagnosis after 18:00.",
        "Alice is free on aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgc2VjcmV0IGJsb2I after 18:00.",
        "Alice is free on Friday after 18:00. Also her PIN is 123456789.",
    ];
    all(texts.map(|text| {
        let out = Outgoing {
            tenant: &alice,
            to: &bob,
            text,
            attachments: &[],
        };
        expect(mandate::admit_open(&m, out, false, &mut ledger, NOW), |e| {
            *e == OpenDenied::NoTemplate
        })
    }))
}

pub(crate) fn open_rate() -> Outcome {
    let m = open_mandate();
    let (alice, bob) = (tenant("alice"), peer("bob"));
    let mut ledger = RateLedger::default();
    let out = Outgoing {
        tenant: &alice,
        to: &bob,
        text: "Alice is free on Friday after 18:00.",
        attachments: &[],
    };
    for i in 0..3 {
        if let Err(e) = mandate::admit_open(&m, out, false, &mut ledger, NOW + i) {
            return Outcome::Fail(format!("legitimate message {i} refused: {e:?}"));
        }
    }
    expect(
        mandate::admit_open(&m, out, false, &mut ledger, NOW + 3),
        |e| *e == OpenDenied::Rate,
    )
}

pub(crate) fn second_open() -> Outcome {
    let mut s = OpenSlots::default();
    let (alice, bob) = (tenant("alice"), peer("bob"));
    if let Err(e) = s.present(&alice, &bob, nonce(7), NOW + 1800, NOW) {
        return Outcome::Fail(format!("first presentation refused: {e:?}"));
    }
    expect(
        s.present(&alice, &bob, nonce(8), NOW + 1800, NOW + 1),
        |e| *e == SlotError::PreviousNotRefused,
    )
}
