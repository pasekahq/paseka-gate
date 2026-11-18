//! Attacks on risk evaluation, the agent contract, shelves, envelopes and tenancy.

use paseka_core::draft;
use paseka_core::envelope::{EnvelopeError, Inbound};
use paseka_core::hash::content_sha256;
use paseka_core::nonce::{Binding, NonceBook, NonceError};
use paseka_core::risk::{self, OutputKind, OwnerRules, Required};
use paseka_core::shelf::{self, ShareError, Shelf};
use paseka_core::token::{self, TokenError};
use paseka_core::trust::{self, Decision, Outbound, Trust};
use paseka_proto::draft::{Draft, DraftState};
use paseka_proto::envelope::{Body, ENVELOPE_V, Envelope};
use paseka_proto::jws::TYP_ENVELOPE;
use paseka_proto::mandate::Mandate;
use paseka_proto::tools::{ShareArgs, TOOL_NAMES, ToolCall};
use paseka_proto::{DocId, DraftId, GateId, Level, UnixSecs};

use crate::fixture::{Gate, NOW, closed, key, nonce, peer, sign, tenant};
use crate::{Outcome, all, expect};

const CANARY: &str = "PASEKA-CANARY-7f3a9c";

fn rules() -> OwnerRules {
    let mut r = OwnerRules::default();
    r.add_canary(CANARY).expect("canary long enough");
    r
}

fn free(text: &str) -> risk::Draft<'_> {
    risk::Draft {
        text,
        kind: OutputKind::FreeText,
        attachments: 0,
        new_recipient: false,
        sources: &[],
        fuzzy_hint: None,
    }
}

fn blocked(text: &str) -> Outcome {
    let a = risk::assess(&rules(), &free(text));
    match trust::decide(Trust::T3, Outbound::FreeText, &a, true) {
        Decision::Block => Outcome::Pass,
        d => Outcome::Fail(format!("{text:?} not blocked: {d:?}")),
    }
}

pub(crate) fn canary_block() -> Outcome {
    let text = format!("Here is the file you asked for: {CANARY}");
    let mut gate = Gate::new();
    let mut mandate = closed();
    mandate.content_sha256 = content_sha256(&text);
    let token = sign(&gate.approver, &Mandate::Closed(mandate));
    gate.nonces.issue(
        &tenant("alice"),
        closed().nonce,
        Binding {
            to: peer("bob"),
            content_sha256: content_sha256(&text),
        },
        NOW + 60,
    );
    let mut d = Draft {
        id: DraftId::new("d1").expect("draft id"),
        tenant: tenant("alice"),
        to: peer("bob"),
        revision: 0,
        text: text.clone(),
        attachments: vec![],
        content_sha256: content_sha256(&text),
        level: Level::A1,
        flags: vec![],
        state: DraftState::Proposed,
    };
    draft::apply_assessment(&mut d, &risk::assess(&rules(), &free(&text)));
    let valid = gate.release(&token, "bob", &text, &[], Level::A2, NOW);
    if valid.is_err() {
        return Outcome::Fail(format!(
            "setup: the mandate itself should verify: {valid:?}"
        ));
    }
    let h = d.content_sha256;
    all([
        blocked(&text),
        expect(draft::approve(&mut d, h, Level::A2), |e| {
            e.from == DraftState::Blocked
        }),
    ])
}

pub(crate) fn canary_obfuscated() -> Outcome {
    all([
        "the marker is paseka canary 7F3A9C",
        "p-a-s-e-k-a\u{200b}canary 7f3a9c",
        "blob UEFTRUtBLUNBTkFSWS03ZjNhOWM",
        "hex 504153454b412d43414e4152592d376633613963",
    ]
    .map(blocked))
}

pub(crate) fn agent_approve_absent() -> Outcome {
    let banned = [
        "approve",
        "owner_approve",
        "agent_approve",
        "consent",
        "sign",
        "release",
        "send",
    ];
    if let Some(name) = TOOL_NAMES.iter().find(|n| banned.contains(n)) {
        return Outcome::Fail(format!("agent tool list offers {name}"));
    }
    all(banned.map(|name| {
        let call = format!(r#"{{"tool":"{name}","args":{{"draft":"d1"}}}}"#);
        expect(serde_json::from_str::<ToolCall>(&call), |_| true)
    }))
}

pub(crate) fn revise_after_approval() -> Outcome {
    let text = "Alice likes the idea.";
    let mut d = Draft {
        id: DraftId::new("d1").expect("draft id"),
        tenant: tenant("alice"),
        to: peer("bob"),
        revision: 0,
        text: text.into(),
        attachments: vec![],
        content_sha256: content_sha256(text),
        level: Level::A1,
        flags: vec![],
        state: DraftState::Proposed,
    };
    draft::apply_assessment(&mut d, &risk::assess(&rules(), &free(text)));
    let h = d.content_sha256;
    if let Err(e) = draft::approve(&mut d, h, Level::A1) {
        return Outcome::Fail(format!("setup approval refused: {e:?}"));
    }
    expect(
        draft::revise(
            &mut d,
            "Alice likes the idea. Her address is 1 Main St.".into(),
        ),
        |e| e.from == DraftState::Approved,
    )
}

pub(crate) fn classifier_says_safe() -> Outcome {
    let d = risk::Draft {
        fuzzy_hint: Some(Level::A0),
        ..free("Alice will be at home alone tonight.")
    };
    match risk::assess(&OwnerRules::default(), &d).required {
        Required::Level(l) if l >= Level::A1 => Outcome::Pass,
        r => Outcome::Fail(format!("free text required only {r:?}")),
    }
}

fn shelves() -> Vec<Shelf> {
    vec![Shelf {
        prefixes: vec![DocId::new("projects").expect("doc id")],
        open_to: [peer("bob")].into(),
    }]
}

fn share(to: &str, doc: &str, note: Option<&str>) -> ShareArgs {
    ShareArgs {
        to: peer(to),
        doc: DocId::new(doc).expect("doc id"),
        section: None,
        note: note.map(Into::into),
    }
}

pub(crate) fn share_outside_shelf() -> Outcome {
    all([
        expect(
            shelf::check_share(&shelves(), &share("bob", "family/health.md", None)),
            |e| *e == ShareError::NotOnOpenShelf,
        ),
        expect(
            shelf::check_share(&shelves(), &share("carol", "projects/a.md", None)),
            |e| *e == ShareError::NotOnOpenShelf,
        ),
        expect(
            shelf::check_share(&shelves(), &share("bob", "projects-private/a.md", None)),
            |e| *e == ShareError::NotOnOpenShelf,
        ),
    ])
}

pub(crate) fn share_path_traversal() -> Outcome {
    let call = r#"{"tool":"share","args":{"to":"bob","doc":"projects/../family/health.md"}}"#;
    expect(serde_json::from_str::<ToolCall>(call), |_| true)
}

pub(crate) fn share_note_smuggle() -> Outcome {
    all([
        "read https://example.org/x?d=secret",
        "her number is +1 555 010 9999",
    ]
    .map(|note| {
        expect(
            shelf::check_share(&shelves(), &share("bob", "projects/a.md", Some(note))),
            |e| *e == ShareError::BadNote,
        )
    }))
}

fn gate_id(seed: u8) -> GateId {
    GateId::new(token::kid_of(&key(seed).verifying_key())).expect("gate id")
}

fn envelope(signer: u8, sent_at: UnixSecs) -> String {
    let env = Envelope {
        v: ENVELOPE_V,
        from: gate_id(signer),
        to: gate_id(2),
        msg_id: nonce(1),
        sent_at,
        body: Body::Question {
            thread: "t1".into(),
            text: "what does alice think about x".into(),
        },
    };
    let k = key(signer);
    token::sign(
        &k,
        &token::kid_of(&k.verifying_key()),
        TYP_ENVELOPE,
        &serde_json::to_vec(&env).expect("serialises"),
    )
}

pub(crate) fn envelope_forged() -> Outcome {
    let mut inbound = Inbound::default();
    inbound.pair(key(1).verifying_key());
    expect(inbound.accept(&envelope(3, NOW), &gate_id(2), NOW), |e| {
        *e == EnvelopeError::Token(TokenError::UnknownKey)
    })
}

pub(crate) fn envelope_replay() -> Outcome {
    let mut inbound = Inbound::default();
    inbound.pair(key(1).verifying_key());
    let t = envelope(1, NOW);
    if let Err(e) = inbound.accept(&t, &gate_id(2), NOW) {
        return Outcome::Fail(format!("first delivery refused: {e:?}"));
    }
    expect(inbound.accept(&t, &gate_id(2), NOW + 5), |e| {
        *e == EnvelopeError::Replay
    })
}

pub(crate) fn cross_tenant_nonce() -> Outcome {
    let mut book = NonceBook::default();
    let b = Binding {
        to: peer("bob"),
        content_sha256: content_sha256("hi"),
    };
    book.issue(&tenant("alice"), nonce(1), b.clone(), NOW + 60);
    expect(book.consume(&tenant("carol"), &nonce(1), &b, NOW), |e| {
        *e == NonceError::Unknown
    })
}
