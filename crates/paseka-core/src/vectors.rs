//! Generator of `contracts/fixtures/vectors/digests.json` and of the closed mandate inside the
//! `wire/envelope` fixtures, from the synthetic seeds.
//!
//! `cargo test -p paseka-core --lib vectors::` fails unless those files are exactly the
//! generator's output; with `PASEKA_WRITE_VECTORS=1` it rewrites them instead.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::Value;

use crate::envelope::seal;
use crate::hash::{Release, approval_challenge, content_sha256, release_digest, sas, sha256};
use crate::mandate::{CLOSED_TTL_SECS, issue};
use crate::testkit::{VECTORS_PATH, event, pairing_id, tenant, thread, ulid};
use crate::token::{self, key_id};
use paseka_proto::envelope::{
    Envelope, EventType, MessageData, Receipt, ReceiptStatus, WireAttachment,
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
struct Signed {
    evidence_bytes_utf8: String,
    closed_mandate: SignedClaims<ClosedMandate>,
    envelope: SignedEnvelope,
    receipt: SignedPayload<Receipt>,
    pair_request: SignedPayload<PairRequest>,
    pair_accept: SignedPayload<PairAccept>,
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
    thread: ThreadId,
    in_reply_to: Option<EventId>,
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
    let first = release_vector(&alice, &bob, thread(1), Some(event(1)), BODY, vec![]);
    let second = release_vector(
        &bob,
        &carol,
        thread(2),
        None,
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
    let signed = signed(&alice, &bob, &first, &challenge, code);
    Vectors {
        description: "Test vectors for PROTOCOL sections 3.2, 3.3, 11. Synthetic data.",
        release_digest: vec![first, second],
        approval_challenge: vec![challenge],
        sas: vec![sas_vector],
        signing_keys: SigningKeys {
            description: "Ed25519 seed = SHA-256('paseka test key <name>'); address = tenant id. \
                          Test only.",
            alice: alice.test_key(),
            bob: bob.test_key(),
            carol: carol.test_key(),
        },
        signed,
    }
}

fn evidence(alice: &Party, challenge: &ChallengeVector) -> String {
    let evidence = TelegramButtonEvidence {
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
    };
    serde_json::to_string(&evidence).expect("evidence serialises")
}

fn pairing_messages(
    alice: &Party,
    bob: &Party,
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

fn signed(
    alice: &Party,
    bob: &Party,
    release: &ReleaseVector,
    challenge: &ChallengeVector,
    code: Nonce,
) -> Signed {
    let evidence_bytes = evidence(alice, challenge);
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
    let (pair_request, pair_accept) = pairing_messages(alice, bob, code);
    Signed {
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
    }
}

fn sign<T: Serialize>(key: &SigningKey, typ: Typ, payload: &T) -> String {
    token::sign(
        key,
        typ,
        &serde_json::to_vec(payload).expect("payload serialises"),
    )
}

fn envelope_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/fixtures/wire/envelope")
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
    let mut text = serde_json::to_string_pretty(&vectors).expect("vectors serialise");
    text.push('\n');
    let mut out = vec![(PathBuf::from(VECTORS_PATH), text)];
    for dir in ["valid", "invalid"] {
        for entry in std::fs::read_dir(envelope_fixtures().join(dir)).expect("fixture dir") {
            let path = entry.expect("dir entry").path();
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
fn digests_json_and_envelope_fixture_mandates_are_the_generator_output() {
    let write = std::env::var_os("PASEKA_WRITE_VECTORS").is_some_and(|v| v == "1");
    for (path, text) in outputs() {
        if write {
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
