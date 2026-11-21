//! Deterministic fixtures for unit tests.

use ed25519_dalek::SigningKey;
use paseka_proto::draft::{DraftKind, DraftState};
use paseka_proto::evidence::Channel;
use paseka_proto::mandate::{Constraints, OpenKind, OpenMandate, OpenProof, Rate};
use paseka_proto::{
    Address, DraftId, EventId, Level, MandateId, Nonce, OpenTrust, PairingId, PeerHandle,
    RequestId, Sha256, TemplateId, TenantId, ThreadId, UnixSecs, V1,
};
use serde_json::Value;

use crate::channel::Channels;
use crate::draft::{Draft, RequestSeed, Revision};
use crate::open::{CONVERSATION_TTL_DEFAULT, Candidate};
use crate::pairing::{Requirement, Verification, VerificationCheck};
use crate::risk::{self, OutputKind, Required};
use crate::source::{Access, Change, Decisions, Source, SourceId, SourceRegistry, Surface};

/// A peer verified by the SAS of a tenant that requires verification: every trust may be granted.
pub(crate) const VERIFIED: VerificationCheck = VerificationCheck {
    peer: Verification::Sas,
    requirement: Requirement::On,
};

/// No registry decisions: every source Ask.
pub(crate) static ASK_ALL: Decisions = Decisions::new();

/// A registered files source.
pub(crate) const FILES: SourceId = SourceId(1);
/// A registered MCP mail source.
pub(crate) const MAIL: SourceId = SourceId(2);
/// A document of [`FILES`].
pub(crate) const DOCUMENT: &str = "The quarterly review found that the merger talks with the northern partner \
    stalled because the valuation gap stayed too wide for both boards to accept.";
/// A near-verbatim quote of [`DOCUMENT`].
pub(crate) const QUOTE: &str = "Between us: the merger talks with the Northern partner stalled, because the valuation gap stayed too wide.";
/// Text with an API key, a hit of the built-in secrets source.
pub(crate) const SECRET: &str = "key sk-abcdefghijklmnopqrstuvwxyz";
/// Text with a Luhn-valid card number, a hit of the built-in personal identifiers source.
pub(crate) const CARD: &str = "card 4111 1111 1111 1111";

/// The protocol test vectors, written by the generator in `vectors.rs`.
pub(crate) const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/fixtures/vectors/digests.json"
);

pub(crate) fn vectors() -> Value {
    serde_json::from_slice(&std::fs::read(VECTORS_PATH).unwrap()).unwrap()
}

/// The signing key of test party `name` in the vectors `v`.
pub(crate) fn seed_key(v: &Value, name: &str) -> SigningKey {
    let hex = v["signing_keys"][name]["seed_hex"].as_str().unwrap();
    SigningKey::from_bytes(&Sha256::from_hex(hex).unwrap().0)
}

pub(crate) fn ulid(prefix: &str, i: u8) -> String {
    format!("{prefix}01JD{i:0>22}")
}

pub(crate) fn tenant(i: u8) -> TenantId {
    TenantId::new(ulid("t_", i)).unwrap()
}

pub(crate) fn address(i: u8) -> Address {
    tenant(i).address()
}

pub(crate) fn draft_id(i: u8) -> DraftId {
    DraftId::new(ulid("d_", i)).unwrap()
}

pub(crate) fn request_id(i: u8) -> RequestId {
    RequestId::new(ulid("r_", i)).unwrap()
}

pub(crate) fn thread(i: u8) -> ThreadId {
    ThreadId::new(ulid("th_", i)).unwrap()
}

pub(crate) fn event(i: u8) -> EventId {
    EventId::new(ulid("e_", i)).unwrap()
}

pub(crate) fn pairing_id(i: u8) -> PairingId {
    PairingId::new(ulid("p_", i)).unwrap()
}

/// Request id and nonce number `i`.
pub(crate) fn seed(i: u8) -> RequestSeed {
    RequestSeed {
        request_id: request_id(i),
        nonce: nonce(i),
    }
}

pub(crate) fn peer(s: &str) -> PeerHandle {
    PeerHandle::new(s).unwrap()
}

pub(crate) fn nonce(i: u8) -> Nonce {
    Nonce::new(format!("nonce{i:0>16}A")).unwrap()
}

/// The MVP approval channels: button, Mini App, Mini App with PIN.
pub(crate) fn mvp_channels() -> Channels {
    Channels::new(vec![
        Channel::TelegramButton,
        Channel::TelegramMiniApp,
        Channel::TelegramMiniAppPin,
    ])
    .unwrap()
}

pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(crate) fn tpl(s: &str) -> TemplateId {
    TemplateId::new(s).unwrap()
}

pub(crate) fn jti(i: u8) -> MandateId {
    MandateId::new(format!("md_01JD{i:0>22}")).unwrap()
}

/// Tenant 1's T1 open mandate `i` to address 2: template `availability`, two messages, `0..1000`.
pub(crate) fn t1(i: u8) -> OpenMandate {
    OpenMandate {
        v: V1,
        kind: OpenKind::Open,
        iss: address(1),
        tenant: tenant(1),
        to: address(2),
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

/// Tenant 1's conversation open mandate `i` to address 2 in thread 1: no rate limit, from 0 for
/// the default duration.
pub(crate) fn conversation(i: u8) -> OpenMandate {
    let t = t1(i);
    OpenMandate {
        exp: CONVERSATION_TTL_DEFAULT,
        trust: OpenTrust::Conversation,
        constraints: Constraints {
            templates: vec![],
            max_len: None,
            rate: Rate::default(),
            thread: Some(thread(1)),
            ..t.constraints
        },
        ..t
    }
}

/// Tenant 1's owner sets `access` for `source` towards `peer` on the settings page at A2.
pub(crate) fn settle(reg: &mut SourceRegistry, source: Source, peer: &Address, access: Access) {
    reg.change(&Change {
        tenant: &tenant(1),
        source,
        peer,
        access,
        surface: Surface::Settings,
        channel: Channel::TelegramMiniApp,
    })
    .unwrap();
}

/// A short rendered template revision to `to`.
pub(crate) fn cand<'a>(to: &'a Address, t: &'a TemplateId, th: &'a ThreadId) -> Candidate<'a> {
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

/// Free text `text` with no attachments, sources, registry decisions, hints, tripwire or open
/// mandate.
pub(crate) fn free(text: &str) -> risk::Draft<'_> {
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

/// An agent revision of `body` without attachments; its release digest is the content hash.
pub(crate) fn rev(body: &str) -> Revision {
    Revision {
        body: body.into(),
        attachments: vec![],
        release_digest: crate::hash::content_sha256(body),
        by_owner: false,
    }
}

/// `n` drafts of tenant `t` to `to`, created at `created_at`, in `state`.
pub(crate) fn drafts(
    t: u8,
    n: u8,
    to: &str,
    created_at: UnixSecs,
    state: DraftState,
) -> Vec<Draft> {
    (0..n)
        .map(|d| Draft {
            to: peer(to),
            state,
            ..awaiting(
                t,
                d,
                "hi",
                created_at,
                created_at + 1000,
                Required::Level(Level::A1),
                created_at,
            )
        })
        .collect()
}

/// Tenant `t`'s free-text draft `d` to bob in thread 1, revision 1 of `body`, alive from
/// `created_at` to `expires`, evaluated at `required` at `now` with the MVP channels, request
/// seed `d` and a 100 s prompt TTL.
pub(crate) fn awaiting(
    t: u8,
    d: u8,
    body: &str,
    created_at: UnixSecs,
    expires: UnixSecs,
    required: Required,
    now: UnixSecs,
) -> Draft {
    let mut draft = Draft {
        tenant: tenant(t),
        id: draft_id(d),
        kind: DraftKind::FreeText,
        to: peer("bob"),
        thread: thread(1),
        in_reply_to: None,
        revision: 1,
        current: rev(body),
        state: DraftState::AwaitingConsent,
        reason: None,
        request: None,
        created_at,
        expires,
        updated_at: created_at,
    };
    draft.evaluated(required, &mvp_channels(), seed(d), now, 100);
    draft
}
