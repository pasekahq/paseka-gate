//! A small deterministic world: tenant alice (sender) and bob (receiver), each with one key.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use paseka_core::draft::{DecisionAttempt, Draft, RequestSeed, Revision};
use paseka_core::envelope::{PeerState, Receiver, seal};
use paseka_core::hash::{Release, content_sha256, release_digest, sha256};
use paseka_core::mandate::{self, CLOSED_TTL_SECS};
use paseka_core::peer::{Grace, PeerKeys, key_revoke_data, key_rotate_data, key_sha256};
use paseka_core::risk::Required;
use paseka_core::token::key_id;
use paseka_proto::draft::{DraftKind, DraftState};
use paseka_proto::envelope::{Envelope, EventType, KeyRotateData, MessageData, WireAttachment};
use paseka_proto::evidence::{Channel, Decision};
use paseka_proto::mandate::{AttachmentMeta, ClosedKind, ClosedMandate, ClosedProof};
use paseka_proto::{
    Address, DraftId, EventId, KeyId, Level, MandateId, Nonce, PairingId, PeerHandle, RequestId,
    Sha256, TenantId, ThreadId, UnixSecs, V1,
};

pub(crate) const NOW: UnixSecs = 1_794_268_830;
pub(crate) const TTL: u64 = 3600;
pub(crate) const BODY: &str = "Bob thinks the plan is fine.\nSee you on Monday.";

fn ulid(prefix: &str, i: u8) -> String {
    format!("{prefix}01JD{i:0>22}")
}

pub(crate) fn tenant(i: u8) -> TenantId {
    TenantId::new(ulid("t_", i)).expect("fixture id")
}

pub(crate) fn address(i: u8) -> Address {
    tenant(i).address()
}

pub(crate) fn request_id(i: u8) -> RequestId {
    RequestId::new(ulid("r_", i)).expect("fixture id")
}

pub(crate) fn thread(i: u8) -> ThreadId {
    ThreadId::new(ulid("th_", i)).expect("fixture id")
}

pub(crate) fn event(i: u8) -> EventId {
    EventId::new(ulid("e_", i)).expect("fixture id")
}

pub(crate) fn jti(i: u8) -> MandateId {
    MandateId::new(ulid("md_", i)).expect("fixture id")
}

pub(crate) fn pairing_id(i: u8) -> PairingId {
    PairingId::new(ulid("p_", i)).expect("fixture id")
}

pub(crate) fn nonce(i: u8) -> Nonce {
    Nonce::new(format!("conformance{i:0>10}A")).expect("fixture nonce")
}

pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(crate) fn kid(k: &SigningKey) -> KeyId {
    key_id(&k.verifying_key())
}

pub(crate) fn seed(i: u8) -> RequestSeed {
    RequestSeed {
        request_id: request_id(i),
        nonce: nonce(i),
    }
}

pub(crate) fn revision(body: &str, attachments: Vec<AttachmentMeta>) -> Revision {
    Revision {
        body: body.into(),
        release_digest: release_digest(&Release {
            tenant: &tenant(1),
            iss: &address(1),
            to: &address(2),
            thread: &thread(1),
            in_reply_to: None,
            content_sha256: content_sha256(body),
            attachments: &attachments,
        }),
        attachments,
        by_owner: false,
    }
}

/// Alice's draft to bob, evaluated at `required` with the MVP channels configured.
pub(crate) fn draft(body: &str, required: Required) -> Draft {
    let mut d = Draft {
        tenant: tenant(1),
        id: DraftId::new(ulid("d_", 1)).expect("fixture id"),
        kind: DraftKind::FreeText,
        to: PeerHandle::new("bob").expect("fixture handle"),
        thread: thread(1),
        in_reply_to: None,
        revision: 1,
        current: revision(body, vec![]),
        state: DraftState::AwaitingConsent,
        reason: None,
        request: None,
        created_at: NOW,
        updated_at: NOW,
    };
    d.evaluated(required, Channel::TelegramMiniApp, seed(1), NOW, TTL);
    d
}

/// An approval of `d`'s live request through `channel` by an approver.
pub(crate) fn approve(d: &Draft, channel: Channel) -> DecisionAttempt<'_> {
    let r = d.request.as_ref().expect("draft awaits consent");
    DecisionAttempt {
        tenant: &d.tenant,
        request_id: &r.request_id,
        nonce: &r.nonce,
        channel,
        approver: true,
        release_digest: d.current.release_digest,
        decision: Decision::Approve,
    }
}

/// Seed of the key alice's pairing committed to.
pub(crate) const ALICE_NEXT: u8 = 4;
/// Seed of the key alice commits to when she rotates to [`ALICE_NEXT`].
pub(crate) const ALICE_AFTER_NEXT: u8 = 5;

/// Gate-to-gate setup: bob's gate receives from alice, whose pairing committed to
/// [`ALICE_NEXT`].
pub(crate) struct Wire {
    pub(crate) recv: Receiver,
    pub(crate) alice: SigningKey,
}

impl Wire {
    pub(crate) fn new() -> Self {
        let alice = key(1);
        let mut recv = Receiver::default();
        recv.add_tenant(tenant(2)).expect("bob is a tenant");
        let keys = PeerKeys::paired(
            alice.verifying_key(),
            Some(key_sha256(&key(ALICE_NEXT).verifying_key())),
        );
        recv.add_peer(&tenant(2), address(1), keys, PeerState::Active)
            .expect("bob records alice");
        Self { recv, alice }
    }
}

pub(crate) fn attachment(name: &str, bytes: &[u8]) -> WireAttachment {
    WireAttachment {
        meta: AttachmentMeta {
            name: name.into(),
            media_type: "text/plain".into(),
            size: bytes.len() as u64,
            sha256: sha256(bytes),
        },
        data: URL_SAFE_NO_PAD.encode(bytes),
    }
}

/// The closed mandate alice's gate issues for `data` sent to bob.
pub(crate) fn mandate_for(data: &MessageData, i: u8) -> ClosedMandate {
    let (alice, bob) = (address(1), address(2));
    let attachments: Vec<AttachmentMeta> =
        data.attachments.iter().map(|a| a.meta.clone()).collect();
    let content = content_sha256(&data.body);
    ClosedMandate {
        v: V1,
        kind: ClosedKind::Closed,
        iss: alice.clone(),
        tenant: tenant(1),
        to: bob.clone(),
        jti: jti(i),
        iat: NOW,
        exp: NOW + CLOSED_TTL_SECS,
        nonce: nonce(i),
        thread: data.thread.clone(),
        in_reply_to: data.in_reply_to.clone(),
        content_sha256: content,
        release_digest: release_digest(&Release {
            tenant: &tenant(1),
            iss: &alice,
            to: &bob,
            thread: &data.thread,
            in_reply_to: data.in_reply_to.as_ref(),
            content_sha256: content,
            attachments: &attachments,
        }),
        attachments,
        level: Level::A1,
        proof: ClosedProof {
            channel: Channel::TelegramButton,
            approved_at: NOW,
            evidence_sha256: Sha256([7; 32]),
            open_mandate: None,
            evidence: None,
        },
    }
}

/// A `message` envelope from alice to bob; `edit` changes the mandate claims before alice signs.
pub(crate) fn message(
    body: &str,
    attachments: Vec<WireAttachment>,
    id: u8,
    edit: impl FnOnce(&mut ClosedMandate),
) -> Envelope<MessageData> {
    let mut data = MessageData {
        thread: thread(1),
        in_reply_to: None,
        body: body.into(),
        attachments,
        mandate: String::new(),
    };
    let mut m = mandate_for(&data, id);
    edit(&mut m);
    data.mandate = mandate::issue(&key(1), &m);
    Envelope {
        v: V1,
        iss: address(1),
        aud: address(2),
        id: event(id),
        kind: EventType::Message,
        iat: NOW,
        data,
    }
}

/// Seals `env` with `signer`.
pub(crate) fn sealed(signer: &SigningKey, env: &Envelope<MessageData>) -> String {
    seal(signer, env)
}

/// Grace alice grants her replaced key: one day.
pub(crate) fn grace() -> Grace {
    Grace::days(1).expect("one day is a valid grace")
}

/// alice's `key.revoke` to bob created at [`NOW`], declaring key `signer` compromised and sealed
/// by it, with the replacement key `new` committing to key `next`, signed by itself, if any.
pub(crate) fn revocation(signer: u8, replacement: Option<(u8, u8)>, id: u8) -> String {
    let new = replacement.map(|(new, next)| (key(new), key_sha256(&key(next).verifying_key())));
    let data = key_revoke_data(
        &address(1),
        &key(signer).verifying_key(),
        new.as_ref().map(|(k, next)| (k, *next)),
    );
    seal(
        &key(signer),
        &Envelope {
            v: V1,
            iss: address(1),
            aud: address(2),
            id: event(id),
            kind: EventType::KeyRevoke,
            iat: NOW,
            data,
        },
    )
}

/// alice's `key.rotate` to bob created at [`NOW`], sealed by `signer`: it names key `new`, its
/// proof is signed by key `proof_by`, and it commits to key `next`.
pub(crate) fn rotation(signer: &SigningKey, new: u8, proof_by: u8, next: u8, id: u8) -> String {
    let mut data: KeyRotateData = key_rotate_data(
        &address(1),
        &key(proof_by),
        key_sha256(&key(next).verifying_key()),
        grace().previous_valid_until(NOW),
    );
    data.new_key = kid(&key(new));
    seal(
        signer,
        &Envelope {
            v: V1,
            iss: address(1),
            aud: address(2),
            id: event(id),
            kind: EventType::KeyRotate,
            iat: NOW,
            data,
        },
    )
}
