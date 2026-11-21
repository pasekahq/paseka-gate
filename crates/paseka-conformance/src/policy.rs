//! Attacks on the agent surface, risk evaluation, open mandates, shelves, tripwire mode and the
//! source registry (SP-1, SP-7 to SP-11, SP-17, SP-23, SP-24).

use std::collections::BTreeSet;

use paseka_core::open::{Candidate, OpenBook, OpenDenied, SlotError, thread_trust};
use paseka_core::risk::{self, CanaryId, OutputKind, OwnerRules, Required};
use paseka_core::shelf::{ShareError, Shelf, check_share};
use paseka_core::source::{
    Access, Change, ChangeError, Decisions, Source, SourceId, SourceKind, SourceRegistry, Surface,
};
use paseka_core::template::field_ok;
use paseka_core::tripwire::{
    ClearAttempt, ClearError, McpWindow, ModeError, TripwireBook, TripwireMode,
};
use paseka_proto::draft::{DraftKind, DraftState};
use paseka_proto::evidence::Channel;
use paseka_proto::mandate::{AttachmentRule, Constraints, OpenKind, OpenMandate, OpenProof, Rate};
use paseka_proto::tools::{FieldSpec, FieldType, FieldValue, ShareInput, TOOL_NAMES, ToolCall};
use paseka_proto::{Address, DocId, Level, OpenTrust, Sha256, ShelfId, TemplateId, TenantId, V1};

use crate::world::{
    BODY, NOW, TTL, address, approve, draft, jti, mvp_channels, revision, seed, tenant, thread,
};
use crate::{Outcome, all, expect};

const CANARY: &str = "PASEKA-CANARY-7f3a9c";
const APPROVAL_WORDS: [&str; 10] = [
    "approve", "deny", "consent", "mandate", "sign", "release", "send", "nonce", "evidence",
    "settings",
];

fn rules() -> OwnerRules {
    let mut r = OwnerRules::default();
    r.add_canary(CanaryId(1), CANARY)
        .expect("canary long enough");
    r
}

static ASK_ALL: Decisions = Decisions::new();

fn free(text: &str) -> risk::Draft<'_> {
    risk::Draft {
        text,
        kind: OutputKind::FreeText,
        attachments: 0,
        new_recipient: false,
        sources: &[],
        decisions: &ASK_ALL,
        fuzzy_hint: None,
        tripwire: false,
        open_mandate: false,
    }
}

pub(crate) fn ca01_no_approve_tool() -> Outcome {
    let mut out = Vec::new();
    for name in TOOL_NAMES {
        if APPROVAL_WORDS.iter().any(|w| name.contains(w)) {
            out.push(Outcome::Fail(format!("tool {name} relates to approval")));
        }
    }
    for name in [
        "approve",
        "deny",
        "issue_mandate",
        "pair",
        "set_trust",
        "settings",
    ] {
        out.push(expect(ToolCall::parse(name, b"{}"), |_| true));
    }
    all(out)
}

pub(crate) fn ca02_proof_like_fields() -> Outcome {
    let calls = [
        ("propose", r#"{"to":"bob","body":"hi""#),
        (
            "revise",
            r#"{"draft_id":"d_01JD0000000000000000000001","revision":1,"body":"hi""#,
        ),
        (
            "share",
            r#"{"to":"bob","doc":"doc_01JD0000000000000000000001""#,
        ),
    ];
    all(calls.iter().flat_map(|(tool, head)| {
        ["approved", "proof", "mandate", "nonce", "evidence", "level"].map(|f| {
            let json = format!(r#"{head},"{f}":true}}"#);
            expect(ToolCall::parse(tool, json.as_bytes()), |_| true)
        })
    }))
}

pub(crate) fn ca18_classifier_says_safe() -> Outcome {
    let d = risk::Draft {
        fuzzy_hint: Some(Level::A0),
        ..free("I think the plan is fine.")
    };
    match risk::assess(&rules(), &d).required {
        Required::Level(Level::A1) => Outcome::Pass,
        other => Outcome::Fail(format!("free text at {other:?}")),
    }
}

pub(crate) fn ca19_canary_blocks() -> Outcome {
    all([
        format!("Here is the file: {CANARY}"),
        "the marker is paseka canary 7F3A9C".into(),
        "blob UEFTRUtBLUNBTkFSWS03ZjNhOWM".into(),
        "hex 504153454b412d43414e4152592d376633613963".into(),
    ]
    .map(|t| match risk::assess(&rules(), &free(&t)).required {
        Required::Block => Outcome::Pass,
        Required::Level(l) => Outcome::Fail(format!("{t:?} at {l}")),
    }))
}

pub(crate) fn ca20_owner_edit_with_canary() -> Outcome {
    let edited = format!("{BODY} {CANARY}");
    let mut d = draft(BODY, Required::Level(Level::A2));
    let required = risk::assess(&rules(), &free(&edited)).required;
    d.evaluated(required, &mvp_channels(), seed(2), NOW, TTL);
    match d.state {
        DraftState::Blocked => Outcome::Pass,
        s => Outcome::Fail(format!("owner edit with canary is {s:?}")),
    }
}

pub(crate) fn ca22_no_oracle() -> Outcome {
    let leaks = [
        "level",
        "flag",
        "nonce",
        "request",
        "evidence",
        "mandate",
        "detector",
        "challenge",
    ];
    let mut d = draft(&format!("x {CANARY}"), Required::Block);
    d.evaluated(Required::Block, &mvp_channels(), seed(1), NOW, TTL);
    let trust = thread_trust(
        &OpenBook::default(),
        &[],
        &tenant(1),
        &address(2),
        &thread(1),
        false,
        NOW,
    );
    let views = [
        d.view(None, trust),
        draft(BODY, Required::Level(Level::A2)).view(None, trust),
    ];
    all(views.iter().map(|v| {
        let json = serde_json::to_value(v).expect("view serialises");
        let keys: Vec<&String> = json.as_object().expect("object").keys().collect();
        match keys.iter().find(|k| leaks.iter().any(|l| k.contains(l))) {
            Some(k) => Outcome::Fail(format!("agent view exposes {k}")),
            None => Outcome::Pass,
        }
    }))
}

pub(crate) fn ca24_no_settings_side_path() -> Outcome {
    let settings = [
        "peer",
        "trust",
        "dictionary",
        "canary",
        "approver",
        "shelf",
        "template",
        "policy",
    ];
    let writers: Vec<&str> = TOOL_NAMES
        .into_iter()
        .filter(|n| settings.iter().any(|s| n.contains(s)) && *n != "peers")
        .collect();
    if writers.is_empty() {
        Outcome::Pass
    } else {
        Outcome::Fail(format!("tools touching settings: {writers:?}"))
    }
}

fn template() -> TemplateId {
    TemplateId::new("availability").expect("fixture id")
}

fn open_t1(i: u8, max_messages: u32) -> OpenMandate {
    OpenMandate {
        v: V1,
        kind: OpenKind::Open,
        iss: address(1),
        tenant: tenant(1),
        to: address(2),
        jti: jti(i),
        iat: NOW,
        nbf: NOW,
        exp: NOW + 3600,
        trust: OpenTrust::T1,
        signed_at_level: Level::A2,
        constraints: Constraints {
            templates: vec![template()],
            max_len: Some(200),
            attachments: Some(AttachmentRule::None),
            private_sources: None,
            rate: Rate {
                max_messages: Some(max_messages),
                per_hour: Some(max_messages),
                per_day: None,
            },
            topics: vec![],
            shelves: vec![],
            thread: None,
        },
        proof: OpenProof {
            channel: Channel::TelegramMiniApp,
            approved_at: NOW,
            evidence_sha256: Sha256([1; 32]),
        },
    }
}

fn active(m: &OpenMandate) -> OpenBook {
    let mut b = OpenBook::default();
    b.present(m, NOW).expect("first presentation");
    b.activate(m).expect("pending");
    b
}

pub(crate) fn ca25_open_mandate_bounds() -> Outcome {
    let m = open_t1(1, 2);
    let mut book = active(&m);
    let (to, t, th) = (address(2), template(), thread(1));
    let c = Candidate {
        to: &to,
        kind: DraftKind::Template,
        template: Some(&t),
        shelf: None,
        thread: &th,
        body_len: 20,
        foreign_attachments: false,
        private_sources: false,
    };
    book.consume(&m, NOW);
    book.consume(&m, NOW + 1);
    all([
        expect(book.matches(&m, &c, false, NOW + 2), |e| {
            *e == OpenDenied::Rate
        }),
        expect(active(&m).matches(&m, &c, false, m.exp), |e| {
            *e == OpenDenied::Inactive
        }),
        expect(
            active(&m).matches(&m, &Candidate { body_len: 201, ..c }, false, NOW),
            |e| *e == OpenDenied::Constraint,
        ),
    ])
}

pub(crate) fn ca26_template_field_smuggle() -> Outcome {
    let spec = FieldSpec {
        kind: FieldType::ShortText,
        values: vec![],
        min: None,
        max: None,
        max_len: Some(64),
    };
    all([
        "see https://example.org/x",
        "account 12345678",
        "data:text/html,x",
    ]
    .map(|v| {
        if field_ok(&spec, &FieldValue::Text(v.into())) {
            Outcome::Fail(format!("field accepted {v:?}"))
        } else {
            Outcome::Pass
        }
    }))
}

pub(crate) fn ca27_revoked_mandate() -> Outcome {
    let m = open_t1(1, 10);
    let mut book = active(&m);
    book.revoke(&m.tenant, &m.jti);
    let (to, t, th) = (address(2), template(), thread(1));
    let c = Candidate {
        to: &to,
        kind: DraftKind::Template,
        template: Some(&t),
        shelf: None,
        thread: &th,
        body_len: 20,
        foreign_attachments: false,
        private_sources: false,
    };
    expect(book.matches(&m, &c, false, NOW + 1), |e| {
        *e == OpenDenied::Inactive
    })
}

pub(crate) fn ca28_second_open_mandate() -> Outcome {
    let mut book = OpenBook::default();
    if book.present(&open_t1(1, 10), NOW).is_err() {
        return Outcome::Fail("setup: first presentation refused".into());
    }
    expect(book.present(&open_t1(2, 10), NOW + 1), |e| {
        *e == SlotError::PreviousPending
    })
}

fn share(doc: &str, note: Option<&str>) -> Result<ShareInput, String> {
    let mut v = serde_json::json!({"to": "bob", "doc": doc});
    if let Some(n) = note {
        v["note"] = n.into();
    }
    match ToolCall::parse("share", v.to_string().as_bytes()) {
        Ok(ToolCall::Share(s)) => Ok(s),
        Ok(other) => Err(format!("parsed as {other:?}")),
        Err(e) => Err(e.0),
    }
}

fn shelves() -> (Vec<Shelf>, ShelfId) {
    let doc = |i: u8| DocId::new(format!("doc_01JD{i:0>22}")).expect("fixture id");
    let sh = |i: u8| ShelfId::new(format!("sh_01JD{i:0>22}")).expect("fixture id");
    (
        vec![
            Shelf {
                id: sh(1),
                docs: BTreeSet::from([doc(1)]),
            },
            Shelf {
                id: sh(2),
                docs: BTreeSet::from([doc(2)]),
            },
        ],
        sh(1),
    )
}

pub(crate) fn ca29_share_outside_shelf() -> Outcome {
    let (shelves, open) = shelves();
    let open = BTreeSet::from([&open]);
    let check = |doc: &str| match share(doc, None) {
        Ok(s) => expect(check_share(&shelves, &open, &s), |e| {
            *e == ShareError::NotFound
        }),
        Err(e) => Outcome::Fail(format!("setup: {e}")),
    };
    all([
        check("doc_01JD0000000000000000000002"),
        check("doc_01JD0000000000000000000009"),
        expect(share("notes/../secrets.md", None), |_| true),
    ])
}

pub(crate) fn ca30_share_note_smuggle() -> Outcome {
    let (shelves, open) = shelves();
    let open = BTreeSet::from([&open]);
    let doc = "doc_01JD0000000000000000000001";
    let long = "a".repeat(201);
    let note = |n: &str| match share(doc, Some(n)) {
        Ok(s) => expect(check_share(&shelves, &open, &s), |e| {
            *e == ShareError::BadNote
        }),
        Err(e) => Outcome::Fail(format!("setup: {e}")),
    };
    all([
        note("see https://example.org/x"),
        note("blob aGVsbG8gd29ybGQ1"),
        expect(share(doc, Some(&long)), |_| true),
    ])
}

pub(crate) fn ca40_invisible_characters() -> Outcome {
    all(
        ["ok\u{202e}txt.exe", "hi\u{200b}there", "a\u{0007}b"].map(|t| {
            match risk::assess(&rules(), &free(t)).required {
                Required::Level(l) if l >= Level::A2 => Outcome::Pass,
                other => Outcome::Fail(format!("{t:?} at {other:?}")),
            }
        }),
    )
}

pub(crate) fn ca41_over_prompt_capacity() -> Outcome {
    let long = "word ".repeat(1000);
    match risk::assess(&rules(), &free(&long)).required {
        Required::Level(l) if l >= Level::A2 => Outcome::Pass,
        other => Outcome::Fail(format!("{} bytes at {other:?}", long.len())),
    }
}

pub(crate) fn ca53_clear_tripwire_without_pin() -> Outcome {
    let body = format!("{BODY} {CANARY}");
    let assessed = risk::assess(&rules(), &free(&body));
    let d = draft(&body, assessed.required);
    let mut book = TripwireBook::default();
    let window = McpWindow {
        from: NOW - 30,
        until: NOW,
    };
    if book.canary_hit(&d, &assessed, window, NOW).is_none() || !book.in_effect(&d.tenant) {
        return Outcome::Fail("setup: canary hit did not enter tripwire mode".into());
    }
    let req = match book.request_clear(&d.tenant, seed(2), NOW + 1, TTL) {
        Ok(r) => r,
        Err(e) => return Outcome::Fail(format!("setup: clear request refused: {e:?}")),
    };
    let by = |channel| ClearAttempt {
        tenant: &d.tenant,
        request_id: &req.request_id,
        nonce: &req.nonce,
        channel,
        approver: true,
    };
    let mut out: Vec<Outcome> = [
        Channel::TelegramButton,
        Channel::TelegramMiniApp,
        Channel::OpenMandate,
    ]
    .map(|c| {
        expect(book.clear(&by(c), NOW + 2), |e| {
            *e == ClearError::ChannelTooWeak
        })
    })
    .into();
    out.push(expect(
        book.set_mode(
            &d.tenant,
            TripwireMode::DraftBlockOnly,
            Channel::TelegramMiniApp,
        ),
        |e| *e == ModeError::TripwireActive,
    ));
    out.extend(
        TOOL_NAMES
            .into_iter()
            .filter(|n| n.contains("tripwire") || n.contains("clear"))
            .map(|n| Outcome::Fail(format!("agent tool {n} reaches tripwire mode"))),
    );
    out.push(expect(ToolCall::parse("clear_tripwire", b"{}"), |_| true));
    if !book.in_effect(&d.tenant) {
        out.push(Outcome::Fail("tripwire mode cleared without PIN".into()));
    }
    if book
        .clear(&by(Channel::TelegramMiniAppPin), NOW + 3)
        .is_err()
    {
        out.push(Outcome::Fail("a PIN decision did not clear".into()));
    }
    all(out)
}

const SECRET_DOC: SourceId = SourceId(1);
const SECRET_TEXT: &str = "The quarterly review found that the merger talks with the northern partner \
    stalled because the valuation gap stayed too wide for both boards to accept.";
const LEAK: &str = "Between us: the merger talks with the Northern partner stalled, because the valuation gap stayed too wide.";

fn conversation(i: u8) -> OpenMandate {
    let m = open_t1(i, 10);
    OpenMandate {
        exp: NOW + 1800,
        trust: OpenTrust::Conversation,
        constraints: Constraints {
            templates: vec![],
            max_len: None,
            attachments: None,
            rate: Rate::default(),
            thread: Some(thread(1)),
            ..m.constraints
        },
        ..m
    }
}

/// Alice's gate with a registered document that is Never towards bob.
struct NeverSource {
    tenant: TenantId,
    bob: Address,
    registry: SourceRegistry,
    rules: OwnerRules,
}

impl NeverSource {
    fn new() -> Result<Self, Outcome> {
        let (tenant, bob) = (tenant(1), address(2));
        let mut registry = SourceRegistry::default();
        let mut rules = rules();
        rules.add_fingerprint(SECRET_DOC, SECRET_TEXT);
        registry
            .register(&tenant, SECRET_DOC, SourceKind::Files)
            .map_err(|e| Outcome::Fail(format!("setup: register refused: {e:?}")))?;
        registry
            .change(&Change {
                tenant: &tenant,
                source: Source::Registered(SECRET_DOC),
                peer: &bob,
                access: Access::Never,
                surface: Surface::Settings,
                channel: Channel::TelegramMiniApp,
            })
            .map_err(|e| Outcome::Fail(format!("setup: Never refused in settings: {e:?}")))?;
        Ok(Self {
            tenant,
            bob,
            registry,
            rules,
        })
    }

    /// The required level of the leaking text to bob.
    fn required(&self, open_mandate: bool) -> Required {
        let decisions = self.registry.towards(&self.tenant, &self.bob);
        let d = risk::Draft {
            decisions: &decisions,
            open_mandate,
            ..free(LEAK)
        };
        risk::assess(&self.rules, &d).required
    }
}

fn ca54_owner_approval(w: &NeverSource) -> Outcome {
    let mut d = draft(BODY, Required::Level(Level::A1));
    let prompt = d.clone();
    if d.revise(1, revision(LEAK, vec![]), NOW + 1).is_err() {
        return Outcome::Fail("setup: revise refused".into());
    }
    d.evaluated(w.required(false), &mvp_channels(), seed(2), NOW + 1, TTL);
    let mut by_pin = approve(&prompt, Channel::TelegramMiniAppPin);
    by_pin.release_digest = d.current.release_digest;
    if d.decide(&by_pin, NOW + 2).is_ok() || d.release(NOW + 2).is_ok() {
        return Outcome::Fail("owner approval released a Never source".into());
    }
    match d.state {
        DraftState::Blocked => Outcome::Pass,
        s => Outcome::Fail(format!("Never source draft is {s:?}")),
    }
}

fn ca54_open_mandate(w: &NeverSource) -> Outcome {
    let m = conversation(1);
    let th = thread(1);
    let c = Candidate {
        to: &w.bob,
        kind: DraftKind::FreeText,
        template: None,
        shelf: None,
        thread: &th,
        body_len: LEAK.len(),
        foreign_attachments: false,
        private_sources: false,
    };
    if let Err(e) = active(&m).matches(&m, &c, false, NOW + 1) {
        return Outcome::Fail(format!("setup: open mandate does not match: {e:?}"));
    }
    match w.required(true) {
        Required::Block => Outcome::Pass,
        Required::Level(l) => Outcome::Fail(format!("under an open mandate at {l}")),
    }
}

fn ca54_lift_outside_settings(w: &mut NeverSource) -> Outcome {
    let (tenant, bob) = (w.tenant.clone(), w.bob.clone());
    let lift = |surface, channel| Change {
        tenant: &tenant,
        source: Source::Registered(SECRET_DOC),
        peer: &bob,
        access: Access::Allow,
        surface,
        channel,
    };
    let mut out = vec![
        expect(
            w.registry
                .change(&lift(Surface::Prompt, Channel::TelegramMiniAppPin)),
            |e| *e == ChangeError::NeverOnlyInSettings,
        ),
        expect(
            w.registry
                .change(&lift(Surface::Settings, Channel::OpenMandate)),
            |e| *e == ChangeError::ChannelTooWeak,
        ),
    ];
    out.extend(
        TOOL_NAMES
            .into_iter()
            .filter(|n| n.contains("source") || n.contains("allow"))
            .map(|n| Outcome::Fail(format!("agent tool {n} reaches the source registry"))),
    );
    if w.required(true) != Required::Block {
        out.push(Outcome::Fail("a refused change lifted Never".into()));
    }
    all(out)
}

pub(crate) fn ca54_never_source_leaves() -> Outcome {
    let mut w = match NeverSource::new() {
        Ok(w) => w,
        Err(o) => return o,
    };
    all([
        ca54_owner_approval(&w),
        ca54_open_mandate(&w),
        ca54_lift_outside_settings(&mut w),
    ])
}
