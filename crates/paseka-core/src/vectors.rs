//! Generator of `contracts/fixtures/vectors/digests.json`, of the closed mandate inside the
//! `wire/envelope` fixtures, of the `mandate/closed` and `evidence/telegram-button` fixtures, of
//! the `key.rotate`, `key.revoke`, `wire/key-proof` and `wire/key-replacement` fixtures, and of
//! the `pairing/accept` fixture with a malformed commitment, from the synthetic seeds.
//!
//! `cargo test -p paseka-core --lib vectors::` fails unless those files are exactly the
//! generator's output; with `PASEKA_WRITE_VECTORS=1` it rewrites them instead.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::Value;

use crate::draft::{DRAFT_LIFETIME_DEFAULT, DRAFT_LIFETIME_RANGE, draft_expires};
use crate::envelope::seal;
use crate::hash::{
    Release, approval_challenge, content_sha256, key_change_sas, release_digest, sas, sha256,
};
use crate::mandate::{CLOSED_TTL_SECS, issue};
use crate::peer::{Grace, key_revoke_data, key_rotate_data, key_sha256};
use crate::testkit::{VECTORS_PATH, event, pairing_id, tenant, thread, ulid};
use crate::token::{self, key_id};
use paseka_proto::envelope::{
    Envelope, EventType, KeyProof, KeyReplacementProof, KeyRevokeData, KeyRotateData, MessageData,
    Receipt, ReceiptStatus, WireAttachment,
};
use paseka_proto::evidence::{Channel, Decision, RequestBinding, TelegramButtonEvidence};
use paseka_proto::jws::Typ;
use paseka_proto::mandate::{AttachmentMeta, ClosedKind, ClosedMandate, ClosedProof};
use paseka_proto::pairing::{PairAccept, PairAcceptType, PairRequest, PairRequestType};
use paseka_proto::{
    Address, EventId, KeyId, Level, MandateId, Nonce, RequestId, Sha256, TenantId, ThreadId,
    UnixSecs, V1,
};

const AT: UnixSecs = 1_794_268_830;
const BODY: &str = "Bob thinks the plan is fine.\nSee you on Monday.";

#[derive(Serialize)]
struct Vectors {
    description: &'static str,
    release_digest: Vec<ReleaseVector>,
    approval_challenge: Vec<ChallengeVector>,
    sas: Vec<SasVector>,
    key_change_sas: Vec<KeyChangeSasVector>,
    signing_keys: SigningKeys,
    signed: Signed,
}

#[derive(Serialize)]
struct ReleaseInput {
    tenant: TenantId,
    iss: Address,
    to: Address,
    thread: ThreadId,
    in_reply_to: Option<EventId>,
    expires: UnixSecs,
    body: String,
    body_utf8_hex: String,
    attachments: Vec<WireAttachment>,
}

#[derive(Serialize)]
struct ReleaseVector {
    input: ReleaseInput,
    content_sha256: Sha256,
    release_digest: Sha256,
}

#[derive(Serialize)]
struct ChallengeInput {
    tenant: TenantId,
    request_id: RequestId,
    release_digest: Sha256,
    nonce: Nonce,
    level: Level,
}

#[derive(Serialize)]
struct ChallengeVector {
    input: ChallengeInput,
    challenge: Sha256,
}

#[derive(Serialize)]
struct SasInput {
    inviter_key: KeyId,
    invitee_key: KeyId,
    code: Nonce,
}

#[derive(Serialize)]
struct SasVector {
    input: SasInput,
    sas: String,
}

#[derive(Serialize)]
struct KeyChangeSasInput {
    changing: Address,
    peer: Address,
    old_key: KeyId,
    new_key: KeyId,
}

#[derive(Serialize)]
struct KeyChangeSasVector {
    input: KeyChangeSasInput,
    sas: String,
}

#[derive(Serialize)]
struct TestKey {
    seed_hex: String,
    key_id: KeyId,
    address: Address,
}

#[derive(Serialize)]
struct SigningKeys {
    description: &'static str,
    alice: TestKey,
    bob: TestKey,
    carol: TestKey,
    #[serde(rename = "alice-2")]
    alice_2: TestKey,
    #[serde(rename = "alice-3")]
    alice_3: TestKey,
}

#[derive(Serialize)]
struct SignedClaims<T> {
    claims: T,
    compact: String,
}

#[derive(Serialize)]
struct SignedPayload<T> {
    payload: T,
    compact: String,
}

#[derive(Serialize)]
struct SignedEnvelope {
    payload: Envelope<MessageData>,
    compact: String,
    envelope_sha256: Sha256,
}

#[derive(Serialize)]
struct SignedKeyRotate {
    payload: Envelope<KeyRotateData>,
    proof_payload: KeyProof,
    compact: String,
}

#[derive(Serialize)]
struct SignedKeyRevoke {
    payload: Envelope<KeyRevokeData>,
    replacement_payload: KeyReplacementProof,
    compact: String,
}

#[derive(Serialize)]
struct Signed {
    #[serde(skip)]
    evidence: TelegramButtonEvidence,
    evidence_bytes_utf8: String,
    closed_mandate: SignedClaims<ClosedMandate>,
    envelope: SignedEnvelope,
    receipt: SignedPayload<Receipt>,
    pair_request: SignedPayload<PairRequest>,
    pair_accept: SignedPayload<PairAccept>,
    key_rotate: SignedKeyRotate,
    key_revoke: SignedKeyRevoke,
}

struct Party {
    key: SigningKey,
    seed: Sha256,
    tenant: TenantId,
}

impl Party {
    fn new(name: &str, i: u8) -> Self {
        let seed = sha256(format!("paseka test key {name}").as_bytes());
        Self {
            key: SigningKey::from_bytes(&seed.0),
            seed,
            tenant: tenant(i),
        }
    }

    fn kid(&self) -> KeyId {
        key_id(&self.key.verifying_key())
    }

    fn address(&self) -> Address {
        self.tenant.address()
    }

    fn test_key(&self) -> TestKey {
        TestKey {
            seed_hex: self.seed.to_hex(),
            key_id: self.kid(),
            address: self.address(),
        }
    }
}

fn b64u_nonce(bytes: &[u8; 16]) -> Nonce {
    Nonce::new(URL_SAFE_NO_PAD.encode(bytes)).expect("16 bytes encode to a nonce")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").expect("writing to a String succeeds");
        s
    })
}

fn attachment(name: &str, media_type: &str, bytes: &[u8]) -> WireAttachment {
    WireAttachment {
        meta: AttachmentMeta {
            name: name.into(),
            media_type: media_type.into(),
            size: bytes.len() as u64,
            sha256: sha256(bytes),
        },
        data: URL_SAFE_NO_PAD.encode(bytes),
    }
}

fn release_vector(
    from: &Party,
    to: &Party,
    (thread, in_reply_to): (ThreadId, Option<EventId>),
    expires: UnixSecs,
    body: &str,
    attachments: Vec<WireAttachment>,
) -> ReleaseVector {
    let content = content_sha256(body);
    let metas: Vec<AttachmentMeta> = attachments.iter().map(|a| a.meta.clone()).collect();
    let input = ReleaseInput {
        tenant: from.tenant.clone(),
        iss: from.address(),
        to: to.address(),
        thread,
        in_reply_to,
        expires,
        body: body.into(),
        body_utf8_hex: hex(body.as_bytes()),
        attachments,
    };
    let digest = release_digest(&Release {
        tenant: &input.tenant,
        iss: &input.iss,
        to: &input.to,
        thread: &input.thread,
        in_reply_to: input.in_reply_to.as_ref(),
        expires: input.expires,
        content_sha256: content,
        attachments: &metas,
    });
    ReleaseVector {
        input,
        content_sha256: content,
        release_digest: digest,
    }
}

fn generate() -> Vectors {
    let (alice, bob, carol) = (
        Party::new("alice", 1),
        Party::new("bob", 2),
        Party::new("carol", 3),
    );
    let (alice_2, alice_3) = (Party::new("alice-2", 1), Party::new("alice-3", 1));
    let first = release_vector(
        &alice,
        &bob,
        (thread(1), Some(event(1))),
        draft_expires(AT - 600, DRAFT_LIFETIME_DEFAULT).expect("default lifetime"),
        BODY,
        vec![],
    );
    let second = release_vector(
        &bob,
        &carol,
        (thread(2), None),
        draft_expires(AT, *DRAFT_LIFETIME_RANGE.start()).expect("shortest lifetime"),
        "Привет, carol! Notes attached ✓",
        vec![
            attachment("notes.md", "text/markdown", b"# Notes\n\nShelf section.\n"),
            attachment("empty.bin", "application/octet-stream", b""),
        ],
    );
    let request_id = RequestId::new(ulid("r_", 1)).expect("fixture id");
    let nonce = b64u_nonce(&std::array::from_fn(|i| u8::try_from(i).expect("< 16")));
    let challenge = ChallengeVector {
        input: ChallengeInput {
            tenant: alice.tenant.clone(),
            request_id: request_id.clone(),
            release_digest: first.release_digest,
            nonce: nonce.clone(),
            level: Level::A1,
        },
        challenge: approval_challenge(
            &alice.tenant,
            &request_id,
            first.release_digest,
            &nonce,
            Level::A1,
        ),
    };
    let code = b64u_nonce(b"defghijklmnopqrs");
    let sas_vector = SasVector {
        sas: sas(&alice.kid(), &bob.kid(), &code),
        input: SasInput {
            inviter_key: alice.kid(),
            invitee_key: bob.kid(),
            code: code.clone(),
        },
    };
    let key_change = KeyChangeSasVector {
        sas: key_change_sas(
            &alice.address(),
            &bob.address(),
            &alice.kid(),
            &alice_3.kid(),
        ),
        input: KeyChangeSasInput {
            changing: alice.address(),
            peer: bob.address(),
            old_key: alice.kid(),
            new_key: alice_3.kid(),
        },
    };
    let signed = signed(&alice, &bob, (&alice_2, &alice_3), &first, &challenge, code);
    Vectors {
        description: "Test vectors for PROTOCOL sections 3.2, 3.3, 10.8, 11. Synthetic data.",
        release_digest: vec![first, second],
        approval_challenge: vec![challenge],
        sas: vec![sas_vector],
        key_change_sas: vec![key_change],
        signing_keys: SigningKeys {
            description: "Ed25519 seed = SHA-256('paseka test key <name>'); address = tenant id. \
                          alice-2 and alice-3 are alice's next keys. Test only.",
            alice: alice.test_key(),
            bob: bob.test_key(),
            carol: carol.test_key(),
            alice_2: alice_2.test_key(),
            alice_3: alice_3.test_key(),
        },
        signed,
    }
}

fn evidence(alice: &Party, challenge: &ChallengeVector) -> TelegramButtonEvidence {
    TelegramButtonEvidence {
        v: 1,
        channel: Channel::TelegramButton,
        level: Level::A1,
        binding: RequestBinding {
            tenant: alice.tenant.clone(),
            request_id: challenge.input.request_id.clone(),
            nonce: challenge.input.nonce.clone(),
            challenge: challenge.challenge,
            decision: Decision::Approve,
            received_at: AT,
        },
        bot_id: 1_000_001,
        chat_id: 2_000_001,
        message_id: 42,
        approver_user_id: 2_000_001,
        callback_query_id: "4200000000000000001".into(),
        update_id: 900_001,
    }
}

/// bob's request and alice's accept, which commits to `alice_next`.
fn pairing_messages(
    alice: &Party,
    bob: &Party,
    alice_next: &Party,
    code: Nonce,
) -> (SignedPayload<PairRequest>, SignedPayload<PairAccept>) {
    let request = PairRequest {
        v: V1,
        kind: PairRequestType::PairRequest,
        id: pairing_id(1),
        iss: bob.address(),
        aud: alice.address(),
        key: bob.kid(),
        code,
        endpoint: "https://gate.example.org/bob".into(),
        name_hint: "Bob".into(),
        iat: AT - 30,
        next_key_sha256: None,
    };
    let request_jws = sign(&bob.key, Typ::Pair, &request);
    let accept = PairAccept {
        v: V1,
        kind: PairAcceptType::PairAccept,
        id: pairing_id(2),
        iss: alice.address(),
        aud: bob.address(),
        key: alice.kid(),
        request_id: request.id.clone(),
        request_sha256: sha256(request_jws.as_bytes()),
        endpoint: "https://gate.example.org/alice".into(),
        iat: AT - 29,
        next_key_sha256: Some(key_sha256(&alice_next.key.verifying_key())),
    };
    (
        SignedPayload {
            payload: request,
            compact: request_jws,
        },
        SignedPayload {
            compact: sign(&alice.key, Typ::Pair, &accept),
            payload: accept,
        },
    )
}

/// alice's `key.rotate` to bob: from her pairing key to `new`, committing to `next`.
fn key_rotate(alice: &Party, bob: &Party, new: &Party, next: &Party) -> SignedKeyRotate {
    let iat = AT + 3600;
    let data = key_rotate_data(
        &alice.address(),
        &new.key,
        key_sha256(&next.key.verifying_key()),
        Grace::default().previous_valid_until(iat),
    );
    let proof_payload = KeyProof {
        v: V1,
        iss: alice.address(),
        new_key: data.new_key.clone(),
        next_key_sha256: data.next_key_sha256,
        previous_valid_until: data.previous_valid_until,
    };
    let payload = Envelope {
        v: V1,
        iss: alice.address(),
        aud: bob.address(),
        id: event(3),
        kind: EventType::KeyRotate,
        iat,
        data,
    };
    SignedKeyRotate {
        compact: seal(&alice.key, &payload),
        payload,
        proof_payload,
    }
}

/// alice's `key.revoke` to bob of her pairing key, replaced by `new`, which commits to `next`.
fn key_revoke(alice: &Party, bob: &Party, new: &Party, next: &Party) -> SignedKeyRevoke {
    let data = key_revoke_data(
        &alice.address(),
        &alice.key.verifying_key(),
        Some((&new.key, key_sha256(&next.key.verifying_key()))),
    );
    let replacement = data.replacement.as_ref().expect("a replacement");
    let replacement_payload = KeyReplacementProof {
        v: V1,
        iss: alice.address(),
        revoked_key: data.revoked_key.clone(),
        new_key: replacement.new_key.clone(),
        next_key_sha256: replacement.next_key_sha256,
    };
    let payload = Envelope {
        v: V1,
        iss: alice.address(),
        aud: bob.address(),
        id: event(4),
        kind: EventType::KeyRevoke,
        iat: AT + 7200,
        data,
    };
    SignedKeyRevoke {
        compact: seal(&alice.key, &payload),
        payload,
        replacement_payload,
    }
}

fn signed(
    alice: &Party,
    bob: &Party,
    (alice_next, alice_after_next): (&Party, &Party),
    release: &ReleaseVector,
    challenge: &ChallengeVector,
    code: Nonce,
) -> Signed {
    let evidence = evidence(alice, challenge);
    let evidence_bytes = serde_json::to_string(&evidence).expect("evidence serialises");
    let i = &release.input;
    let claims = ClosedMandate {
        v: V1,
        kind: ClosedKind::Closed,
        iss: i.iss.clone(),
        tenant: i.tenant.clone(),
        to: i.to.clone(),
        jti: MandateId::new(ulid("md_", 1)).expect("fixture id"),
        iat: AT,
        exp: AT + CLOSED_TTL_SECS,
        nonce: challenge.input.nonce.clone(),
        thread: i.thread.clone(),
        in_reply_to: i.in_reply_to.clone(),
        expires: i.expires,
        content_sha256: release.content_sha256,
        attachments: vec![],
        release_digest: release.release_digest,
        level: Level::A1,
        proof: ClosedProof {
            channel: Channel::TelegramButton,
            approved_at: AT,
            evidence_sha256: sha256(evidence_bytes.as_bytes()),
            open_mandate: None,
            evidence: None,
        },
    };
    let mandate = issue(&alice.key, &claims);
    let envelope = Envelope {
        v: V1,
        iss: alice.address(),
        aud: bob.address(),
        id: event(2),
        kind: EventType::Message,
        iat: AT,
        data: MessageData {
            thread: i.thread.clone(),
            in_reply_to: i.in_reply_to.clone(),
            body: i.body.clone(),
            attachments: vec![],
            mandate: mandate.clone(),
        },
    };
    let envelope_jws = seal(&alice.key, &envelope);
    let envelope_sha256 = sha256(envelope_jws.as_bytes());
    let receipt = Receipt {
        v: V1,
        iss: bob.address(),
        aud: alice.address(),
        id: event(2),
        envelope_sha256,
        received_at: AT + 1,
        status: ReceiptStatus::Accepted,
    };
    let (pair_request, pair_accept) = pairing_messages(alice, bob, alice_next, code);
    Signed {
        evidence,
        evidence_bytes_utf8: evidence_bytes,
        closed_mandate: SignedClaims {
            claims,
            compact: mandate,
        },
        envelope: SignedEnvelope {
            payload: envelope,
            compact: envelope_jws,
            envelope_sha256,
        },
        receipt: SignedPayload {
            compact: sign(&bob.key, Typ::Receipt, &receipt),
            payload: receipt,
        },
        pair_request,
        pair_accept,
        key_rotate: key_rotate(alice, bob, alice_next, alice_after_next),
        key_revoke: key_revoke(alice, bob, alice_next, alice_after_next),
    }
}

fn sign<T: Serialize>(key: &SigningKey, typ: Typ, payload: &T) -> String {
    token::sign(
        key,
        typ,
        &serde_json::to_vec(payload).expect("payload serialises"),
    )
}

fn fixtures(dir: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures")
        .join(dir)
}

fn wire_fixtures() -> PathBuf {
    fixtures("wire")
}

fn json_file<T: Serialize>(value: &T) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("fixture serialises");
    text.push('\n');
    text
}

/// The `key.rotate` envelope fixtures and the `wire/key-proof` fixtures, from the signed vector.
fn key_rotate_fixtures(k: &SignedKeyRotate) -> Vec<(PathBuf, String)> {
    let (envelope, proof) = (
        wire_fixtures().join("envelope"),
        wire_fixtures().join("key-proof"),
    );
    let payload = serde_json::to_value(&k.payload).expect("envelope serialises");
    let mut without_proof = payload.clone();
    without_proof["data"]
        .as_object_mut()
        .expect("data is an object")
        .remove("proof");
    let mut malformed_key = payload;
    malformed_key["data"]["new_key"] = "ed25519:not-a-key".into();
    let mut key_as_sender = serde_json::to_value(&k.proof_payload).expect("proof serialises");
    key_as_sender["iss"] = k.proof_payload.new_key.as_str().into();
    vec![
        (
            envelope.join("valid/key-rotate.json"),
            json_file(&k.payload),
        ),
        (
            envelope.join("invalid/key-rotate-without-proof.json"),
            json_file(&without_proof),
        ),
        (
            envelope.join("invalid/key-rotate-malformed-new-key.json"),
            json_file(&malformed_key),
        ),
        (proof.join("valid/basic.json"), json_file(&k.proof_payload)),
        (
            proof.join("invalid/key-id-as-sender.json"),
            json_file(&key_as_sender),
        ),
    ]
}

/// The `key.revoke` envelope fixtures and the `wire/key-replacement` fixtures, from the signed
/// vector.
fn key_revoke_fixtures(k: &SignedKeyRevoke) -> Vec<(PathBuf, String)> {
    let (envelope, proof) = (
        wire_fixtures().join("envelope"),
        wire_fixtures().join("key-replacement"),
    );
    let payload = serde_json::to_value(&k.payload).expect("envelope serialises");
    let mut alone = payload.clone();
    alone["data"]
        .as_object_mut()
        .expect("data is an object")
        .remove("replacement");
    let mut without_proof = payload.clone();
    without_proof["data"]["replacement"]
        .as_object_mut()
        .expect("replacement is an object")
        .remove("proof");
    let mut malformed_key = payload;
    malformed_key["data"]["revoked_key"] = "ed25519:not-a-key".into();
    let mut key_as_sender = serde_json::to_value(&k.replacement_payload).expect("proof serialises");
    key_as_sender["iss"] = k.replacement_payload.new_key.as_str().into();
    vec![
        (
            envelope.join("valid/key-revoke.json"),
            json_file(&k.payload),
        ),
        (
            envelope.join("valid/key-revoke-without-replacement.json"),
            json_file(&alone),
        ),
        (
            envelope.join("invalid/key-revoke-replacement-without-proof.json"),
            json_file(&without_proof),
        ),
        (
            envelope.join("invalid/key-revoke-malformed-revoked-key.json"),
            json_file(&malformed_key),
        ),
        (
            proof.join("valid/basic.json"),
            json_file(&k.replacement_payload),
        ),
        (
            proof.join("invalid/key-id-as-sender.json"),
            json_file(&key_as_sender),
        ),
    ]
}

/// A `pairing/accept` fixture whose commitment is a key id instead of a SHA-256 hex digest.
fn pair_accept_fixtures(accept: &PairAccept) -> Vec<(PathBuf, String)> {
    let mut key_as_next = serde_json::to_value(accept).expect("accept serialises");
    key_as_next["next_key_sha256"] = accept.key.as_str().into();
    let dir = fixtures("pairing/accept");
    vec![(
        dir.join("invalid/key-id-as-next-key.json"),
        json_file(&key_as_next),
    )]
}

/// The `mandate/closed` fixtures: the signed closed mandate's claims, an A0 variant, and one
/// broken claim per invalid case. `attachment` fills the nine-attachment case and `key` the
/// recipient that is a key id instead of an address.
fn closed_mandate_fixtures(
    m: &ClosedMandate,
    attachment: &AttachmentMeta,
    key: &KeyId,
) -> Vec<(PathBuf, String)> {
    let dir = fixtures("mandate/closed");
    let a0 = ClosedMandate {
        level: Level::A0,
        proof: ClosedProof {
            channel: Channel::OpenMandate,
            evidence_sha256: Sha256([0xab; 32]),
            open_mandate: Some(MandateId::new(ulid("md_", 9)).expect("fixture id")),
            ..m.proof.clone()
        },
        ..m.clone()
    };
    let a0_without_open = ClosedMandate {
        proof: ClosedProof {
            open_mandate: None,
            ..a0.proof.clone()
        },
        ..a0.clone()
    };
    let a1_open_channel = ClosedMandate {
        proof: ClosedProof {
            channel: Channel::OpenMandate,
            ..m.proof.clone()
        },
        ..m.clone()
    };
    let nine = ClosedMandate {
        attachments: vec![attachment.clone(); 9],
        ..m.clone()
    };
    let claims = serde_json::to_value(m).expect("claims serialise");
    let edited = |edit: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut v = claims.clone();
        edit(v.as_object_mut().expect("claims are an object"));
        json_file(&v)
    };
    let mut key_as_to = serde_json::to_value(&a0).expect("claims serialise");
    key_as_to["to"] = key.as_str().into();
    vec![
        (dir.join("valid/a1-button.json"), json_file(m)),
        (dir.join("valid/a0-open-mandate.json"), json_file(&a0)),
        (
            dir.join("valid/unknown-claim-tolerated.json"),
            edited(&|c| {
                c.insert("x_future".into(), serde_json::json!({"any": 1}));
            }),
        ),
        (
            dir.join("invalid/a0-without-open-mandate.json"),
            json_file(&a0_without_open),
        ),
        (
            dir.join("invalid/a1-with-open-mandate-channel.json"),
            json_file(&a1_open_channel),
        ),
        (
            dir.join("invalid/key-id-as-recipient.json"),
            json_file(&key_as_to),
        ),
        (
            dir.join("invalid/kind-open.json"),
            edited(&|c| {
                c.insert("kind".into(), "open".into());
            }),
        ),
        (
            dir.join("invalid/missing-content-sha256.json"),
            edited(&|c| {
                c.remove("content_sha256");
            }),
        ),
        (
            dir.join("invalid/missing-expires.json"),
            edited(&|c| {
                c.remove("expires");
            }),
        ),
        (dir.join("invalid/nine-attachments.json"), json_file(&nine)),
        (
            dir.join("invalid/unknown-level.json"),
            edited(&|c| {
                c.insert("level".into(), "A9".into());
            }),
        ),
        (
            dir.join("invalid/uppercase-hash.json"),
            edited(&|c| {
                c.insert(
                    "content_sha256".into(),
                    m.content_sha256.to_hex().to_uppercase().into(),
                );
            }),
        ),
    ]
}

/// The `evidence/telegram-button` fixtures: the evidence the signed closed mandate's
/// `evidence_sha256` covers, and one broken field per invalid case.
fn telegram_button_fixtures(e: &TelegramButtonEvidence) -> Vec<(PathBuf, String)> {
    let dir = fixtures("evidence/telegram-button");
    let value = serde_json::to_value(e).expect("evidence serialises");
    let mut level_a2 = value.clone();
    level_a2["level"] = "A2".into();
    let mut no_approver = value;
    no_approver
        .as_object_mut()
        .expect("evidence is an object")
        .remove("approver_user_id");
    vec![
        (dir.join("valid/approve.json"), json_file(e)),
        (dir.join("invalid/level-a2.json"), json_file(&level_a2)),
        (
            dir.join("invalid/missing-approver.json"),
            json_file(&no_approver),
        ),
    ]
}

/// `text` of an envelope fixture with its `data.mandate`, if any, replaced by `mandate`; a
/// fixture whose mandate lacks the SD-JWT `~` keeps lacking it.
fn with_mandate(text: &str, mandate: &str) -> String {
    let fixture: Value = serde_json::from_str(text).expect("fixture is JSON");
    let Some(old) = fixture["data"]["mandate"].as_str() else {
        return text.to_owned();
    };
    let new = if old.ends_with('~') {
        mandate
    } else {
        mandate.trim_end_matches('~')
    };
    text.replace(&format!("\"{old}\""), &format!("\"{new}\""))
}

/// Every generated file with its content.
fn outputs() -> Vec<(PathBuf, String)> {
    let vectors = generate();
    let mut out = vec![(PathBuf::from(VECTORS_PATH), json_file(&vectors))];
    out.extend(key_rotate_fixtures(&vectors.signed.key_rotate));
    out.extend(key_revoke_fixtures(&vectors.signed.key_revoke));
    out.extend(pair_accept_fixtures(&vectors.signed.pair_accept.payload));
    out.extend(closed_mandate_fixtures(
        &vectors.signed.closed_mandate.claims,
        &vectors.release_digest[1].input.attachments[0].meta,
        &vectors.signing_keys.bob.key_id,
    ));
    out.extend(telegram_button_fixtures(&vectors.signed.evidence));
    for dir in ["valid", "invalid"] {
        let fixtures = wire_fixtures().join("envelope").join(dir);
        for entry in std::fs::read_dir(fixtures).expect("fixture dir") {
            let path = entry.expect("dir entry").path();
            if out.iter().any(|(p, _)| *p == path) {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("fixture text");
            out.push((
                path,
                with_mandate(&text, &vectors.signed.closed_mandate.compact),
            ));
        }
    }
    out
}

#[test]
fn vectors_and_generated_fixtures_are_the_generator_output() {
    let write = std::env::var_os("PASEKA_WRITE_VECTORS").is_some_and(|v| v == "1");
    for (path, text) in outputs() {
        if write {
            let dir = path.parent().expect("a fixture lives in a directory");
            std::fs::create_dir_all(dir).expect("fixture directory created");
            std::fs::write(&path, &text).expect("generated file written");
            continue;
        }
        let on_disk = std::fs::read_to_string(&path).expect("generated file");
        assert!(
            on_disk == text,
            "{} differs from the generator; run PASEKA_WRITE_VECTORS=1 cargo test -p paseka-core --lib vectors::",
            path.display()
        );
    }
}
