//! Attacks on the gate-to-gate wire (SP-4, SP-12 to SP-15).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use paseka_core::envelope::{MAX_AGE_SECS, PeerConflict, PeerState};
use paseka_core::mandate;
use paseka_core::pairing::{AcceptInvalid, Expected, Verification, verify_accept};
use paseka_core::peer::{KeyChange, NoPendingChange, PeerKeys};
use paseka_core::token;
use paseka_proto::envelope::{ReceiptStatus, WireErrorCode};
use paseka_proto::jws::Typ;
use paseka_proto::pairing::{PairAccept, PairAcceptType, PairRequest, PairRequestType};
use paseka_proto::{Level, Sha256, V1};

use crate::world::{
    ALICE_AFTER_NEXT, ALICE_NEXT, BODY, NOW, Wire, address, attachment, grace, key, kid,
    mandate_for, message, nonce, pairing_id, revocation, rotation, sealed, tenant, thread,
};
use crate::{Outcome, all, expect};

fn code(w: &mut Wire, jws: &str, now: u64, want: WireErrorCode) -> Outcome {
    expect(w.recv.accept(jws, now), |e| *e == want)
}

pub(crate) fn ca12_envelope_replay() -> Outcome {
    let mut w = Wire::new();
    let jws = sealed(&w.alice, &message(BODY, vec![], 1, |_| {}));
    let first = w.recv.accept(&jws, NOW + 1);
    let second = w.recv.accept(&jws, NOW + 2);
    match (first, second) {
        (Ok(a), Ok(b))
            if a.status == ReceiptStatus::Accepted
                && b.status == ReceiptStatus::Duplicate
                && b.event.is_none() =>
        {
            Outcome::Pass
        }
        other => Outcome::Fail(format!("{other:?}")),
    }
}

pub(crate) fn ca31_forged_envelopes() -> Outcome {
    let mut w = Wire::new();
    let carol = key(3);
    if let Err(e) = w.recv.add_peer(
        &tenant(2),
        address(3),
        PeerKeys::paired(carol.verifying_key(), None),
        PeerState::Active,
        Verification::Sas,
    ) {
        return Outcome::Fail(format!("setup: carol not recorded: {e:?}"));
    }
    let env = message(BODY, vec![], 1, |_| {});
    let stranger = key(9);
    let unknown_sender = {
        let mut other = env.clone();
        other.iss = address(9);
        sealed(&stranger, &other)
    };
    let unknown_key = sealed(&stranger, &env);
    let other_peers_key = sealed(&carol, &env);
    let payload = serde_json::to_vec(&env).expect("serialises");
    let alg_none = {
        let h = format!(
            r#"{{"alg":"none","kid":"{}","typ":"paseka-envelope+jwt"}}"#,
            kid(&w.alice)
        );
        format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(h),
            URL_SAFE_NO_PAD.encode(&payload)
        )
    };
    let alg_hs256 = {
        let h = format!(
            r#"{{"alg":"HS256","kid":"{}","typ":"paseka-envelope+jwt"}}"#,
            kid(&w.alice)
        );
        format!(
            "{}.{}.AAAA",
            URL_SAFE_NO_PAD.encode(h),
            URL_SAFE_NO_PAD.encode(&payload)
        )
    };
    let bad_sig = {
        let t = sealed(&w.alice, &env);
        let (head, sig) = t.rsplit_once('.').expect("three parts");
        let flipped = if sig.starts_with('A') { "B" } else { "A" };
        format!("{head}.{flipped}{}", &sig[1..])
    };
    let as_receipt = token::sign(&w.alice, Typ::Receipt, &payload);
    all([
        code(&mut w, &as_receipt, NOW, WireErrorCode::Malformed),
        code(&mut w, &unknown_sender, NOW, WireErrorCode::NotPaired),
        code(&mut w, &unknown_key, NOW, WireErrorCode::BadSignature),
        code(&mut w, &alg_none, NOW, WireErrorCode::Malformed),
        code(&mut w, &alg_hs256, NOW, WireErrorCode::Malformed),
        code(&mut w, &other_peers_key, NOW, WireErrorCode::BadSignature),
        code(&mut w, &bad_sig, NOW, WireErrorCode::BadSignature),
    ])
}

pub(crate) fn ca32_cross_tenant_envelope() -> Outcome {
    let mut w = Wire::new();
    if let Err(e) = w.recv.add_tenant(tenant(3)) {
        return Outcome::Fail(format!("setup: carol not a tenant: {e:?}"));
    }
    let mut env = message(BODY, vec![], 1, |_| {});
    env.aud = address(3);
    let jws = sealed(&w.alice, &env);
    code(&mut w, &jws, NOW, WireErrorCode::NotPaired)
}

pub(crate) fn ca33_wire_windows() -> Outcome {
    let mut w = Wire::new();
    let jws = sealed(&w.alice, &message(BODY, vec![], 1, |_| {}));
    let other = sealed(
        &w.alice,
        &message("Other bytes, same event id.", vec![], 1, |_| {}),
    );
    let stale = code(&mut w, &jws, NOW + MAX_AGE_SECS + 1, WireErrorCode::Stale);
    let future = code(&mut w, &jws, NOW - 400, WireErrorCode::FromFuture);
    let first = w.recv.accept(&jws, NOW).map(|a| a.status);
    if first != Ok(ReceiptStatus::Accepted) {
        return Outcome::Fail(format!("setup: {first:?}"));
    }
    all([
        stale,
        future,
        code(&mut w, &other, NOW + 1, WireErrorCode::Conflict),
    ])
}

pub(crate) fn ca34_mandate_mismatch() -> Outcome {
    let mut w = Wire::new();
    let mut cases = Vec::new();
    let mut other_content = message(BODY, vec![], 1, |_| {});
    other_content.data.body = "Bob thinks the plan is a mistake.".into();
    cases.push((other_content, WireErrorCode::MandateInvalid));
    cases.push((
        message(BODY, vec![], 2, |m| m.to = address(9)),
        WireErrorCode::MandateInvalid,
    ));
    cases.push((
        message(BODY, vec![], 3, |m| m.thread = thread(9)),
        WireErrorCode::MandateInvalid,
    ));
    cases.push((
        message(BODY, vec![], 4, |m| m.exp = m.iat + 3600),
        WireErrorCode::MandateInvalid,
    ));
    cases.push((
        message(BODY, vec![], 5, |m| m.level = Level::A2),
        WireErrorCode::MandateInvalid,
    ));
    cases.push((
        message(BODY, vec![], 6, |m| m.release_digest = Sha256([0; 32])),
        WireErrorCode::MandateInvalid,
    ));
    let mut swapped = message(BODY, vec![attachment("notes.md", b"shelf")], 7, |_| {});
    swapped.data.attachments[0].data = URL_SAFE_NO_PAD.encode(b"other");
    cases.push((swapped, WireErrorCode::MandateInvalid));
    let mut other_signer = message(BODY, vec![], 10, |_| {});
    other_signer.data.mandate = mandate::issue(&key(3), &mandate_for(&other_signer.data, 10));
    cases.push((other_signer, WireErrorCode::MandateInvalid));
    let mut out: Vec<Outcome> = cases
        .into_iter()
        .map(|(env, want)| {
            let jws = sealed(&w.alice, &env);
            code(&mut w, &jws, NOW + 1, want)
        })
        .collect();
    let first = message(BODY, vec![], 8, |_| {});
    let mut reused = message(BODY, vec![], 9, |_| {});
    reused.data.mandate.clone_from(&first.data.mandate);
    let ok = w
        .recv
        .accept(&sealed(&w.alice, &first), NOW + 1)
        .map(|a| a.status);
    if ok != Ok(ReceiptStatus::Accepted) {
        return Outcome::Fail(format!("setup: {ok:?}"));
    }
    let jws = sealed(&w.alice, &reused);
    out.push(code(&mut w, &jws, NOW + 2, WireErrorCode::MandateReplay));
    all(out)
}

pub(crate) fn ca36_pairing_pending() -> Outcome {
    let mut w = Wire::new();
    let keys = PeerKeys::paired(w.alice.verifying_key(), None);
    if let Err(e) = w.recv.add_peer(
        &tenant(2),
        address(1),
        keys,
        PeerState::PendingOwner,
        Verification::NotVerified,
    ) {
        return Outcome::Fail(format!("setup: {e:?}"));
    }
    let jws = sealed(&w.alice, &message(BODY, vec![], 1, |_| {}));
    code(&mut w, &jws, NOW, WireErrorCode::PairingPending)
}

/// An accept from alice's gate to bob's request, signed by `signer` after `edit`.
fn pair_accept(signer: &SigningKey, request: &str, edit: fn(&mut PairAccept)) -> String {
    let mut a = PairAccept {
        v: V1,
        kind: PairAcceptType::PairAccept,
        id: pairing_id(2),
        iss: address(1),
        aud: address(2),
        key: kid(&key(1)),
        request_id: pairing_id(1),
        request_sha256: paseka_core::hash::sha256(request.as_bytes()),
        endpoint: "https://gate.example.org/alice".into(),
        iat: NOW,
        next_key_sha256: None,
    };
    edit(&mut a);
    token::sign(
        signer,
        Typ::Pair,
        &serde_json::to_vec(&a).expect("serialises"),
    )
}

pub(crate) fn ca37_pair_accept_other_key() -> Outcome {
    let (alice, bob, carol) = (key(1), key(2), key(3));
    let request = PairRequest {
        v: V1,
        kind: PairRequestType::PairRequest,
        id: pairing_id(1),
        iss: address(2),
        aud: address(1),
        key: kid(&bob),
        code: nonce(1),
        endpoint: "https://gate.example.org/bob".into(),
        name_hint: "Bob".into(),
        iat: NOW,
        next_key_sha256: None,
    };
    let request = token::sign(
        &bob,
        Typ::Pair,
        &serde_json::to_vec(&request).expect("serialises"),
    );
    let (alice_at, bob_at, uri_key) = (address(1), address(2), kid(&alice));
    let want = Expected {
        inviter: &alice_at,
        inviter_key: &uri_key,
        invitee: &bob_at,
        request: &request,
    };
    if let Err(e) = verify_accept(&pair_accept(&alice, &request, |_| {}), &want) {
        return Outcome::Fail(format!("setup: genuine accept refused: {e:?}"));
    }
    let token = |e: &AcceptInvalid| matches!(e, AcceptInvalid::Token(_));
    all([
        expect(
            verify_accept(&pair_accept(&carol, &request, |_| {}), &want),
            token,
        ),
        expect(
            verify_accept(
                &pair_accept(&carol, &request, |a| a.key = kid(&key(3))),
                &want,
            ),
            token,
        ),
        expect(
            verify_accept(
                &pair_accept(&alice, &request, |a| a.iss = address(3)),
                &want,
            ),
            |e| *e == AcceptInvalid::Inviter,
        ),
    ])
}

/// alice's genuine rotation from key 1 to [`ALICE_NEXT`], accepted by bob at `NOW + 1`.
fn rotate_genuinely(w: &mut Wire) -> Result<(), Outcome> {
    let jws = rotation(&w.alice, ALICE_NEXT, ALICE_NEXT, ALICE_AFTER_NEXT, 200);
    match w.recv.accept(&jws, NOW + 1).map(|a| a.key_change) {
        Ok(Some(KeyChange::Installed)) => Ok(()),
        other => Err(Outcome::Fail(format!("setup: genuine rotation: {other:?}"))),
    }
}

fn alice_current_key(w: &Wire) -> Option<ed25519_dalek::VerifyingKey> {
    w.recv
        .peer_keys(&tenant(2), &address(1))
        .map(|k| *k.current())
}

pub(crate) fn ca48_key_substitution() -> Outcome {
    let mut w = Wire::new();
    let original = alice_current_key(&w);
    let attacker = key(9);
    let proof_by_other_key = rotation(&w.alice, ALICE_NEXT, 9, ALICE_AFTER_NEXT, 200);
    let rotation_refused = code(
        &mut w,
        &proof_by_other_key,
        NOW + 1,
        WireErrorCode::BadSignature,
    );
    let repaired = w.recv.add_peer(
        &tenant(2),
        address(1),
        PeerKeys::paired(attacker.verifying_key(), None),
        PeerState::Active,
        Verification::Sas,
    );
    let own_address = w.recv.add_peer(
        &tenant(2),
        address(2),
        PeerKeys::paired(attacker.verifying_key(), None),
        PeerState::Active,
        Verification::Sas,
    );
    let by_attacker = sealed(&attacker, &message(BODY, vec![], 1, |_| {}));
    let unchanged = if alice_current_key(&w) == original {
        Outcome::Pass
    } else {
        Outcome::Fail("alice's recorded key changed".into())
    };
    all([
        rotation_refused,
        expect(repaired, |e| *e == PeerConflict::OtherKey),
        expect(own_address, |e| *e == PeerConflict::OwnTenant),
        code(&mut w, &by_attacker, NOW + 2, WireErrorCode::BadSignature),
        unchanged,
    ])
}

pub(crate) fn ca49_rotation_not_by_current_key() -> Outcome {
    let mut w = Wire::new();
    let stranger = rotation(&key(9), ALICE_NEXT, ALICE_NEXT, ALICE_AFTER_NEXT, 201);
    let by_stranger = code(&mut w, &stranger, NOW + 1, WireErrorCode::BadSignature);
    if let Err(fail) = rotate_genuinely(&mut w) {
        return fail;
    }
    let by_previous = rotation(&w.alice, ALICE_AFTER_NEXT, ALICE_AFTER_NEXT, 6, 202);
    let previous_refused = code(&mut w, &by_previous, NOW + 2, WireErrorCode::BadSignature);
    let unchanged = if alice_current_key(&w) == Some(key(ALICE_NEXT).verifying_key()) {
        Outcome::Pass
    } else {
        Outcome::Fail("a rotation by the previous key moved alice's key".into())
    };
    all([by_stranger, previous_refused, unchanged])
}

pub(crate) fn ca50_previous_key_after_grace() -> Outcome {
    let mut w = Wire::new();
    if let Err(fail) = rotate_genuinely(&mut w) {
        return fail;
    }
    let until = grace().previous_valid_until(NOW);
    let new = key(ALICE_NEXT);
    let in_grace = w
        .recv
        .accept(
            &sealed(&w.alice, &message(BODY, vec![], 1, |_| {})),
            until - 1,
        )
        .map(|a| a.status);
    if in_grace != Ok(ReceiptStatus::Accepted) {
        return Outcome::Fail(format!("setup: previous key in its grace: {in_grace:?}"));
    }
    let old_envelope = sealed(&w.alice, &message(BODY, vec![], 2, |_| {}));
    let old_mandate = sealed(&new, &message(BODY, vec![], 3, |_| {}));
    all([
        code(&mut w, &old_envelope, until, WireErrorCode::BadSignature),
        code(&mut w, &old_mandate, until, WireErrorCode::MandateInvalid),
    ])
}

/// Seed of the key a thief who stole alice's current key wants peers to accept.
const THIEF: u8 = 9;

fn key_change(w: &mut Wire, jws: &str, now: u64, want: KeyChange) -> Outcome {
    match w.recv.accept(jws, now).map(|a| a.key_change) {
        Ok(Some(got)) if got == want => Outcome::Pass,
        other => Outcome::Fail(format!("want {want:?}, got {other:?}")),
    }
}

fn current_is(w: &Wire, seed: u8, what: &str) -> Outcome {
    if alice_current_key(w) == Some(key(seed).verifying_key()) {
        Outcome::Pass
    } else {
        Outcome::Fail(format!("{what}: alice's current key is not key {seed}"))
    }
}

pub(crate) fn ca51_thief_moves_peer_to_own_key() -> Outcome {
    let mut w = Wire::new();
    let thief = key(THIEF);
    let thief_rotate = rotation(&w.alice, THIEF, THIEF, THIEF, 210);
    let thief_revoke = revocation(1, Some((THIEF, THIEF)), 211);
    let genuine = rotation(&w.alice, ALICE_NEXT, ALICE_NEXT, ALICE_AFTER_NEXT, 212);
    let by_thief = |id| sealed(&thief, &message(BODY, vec![], id, |_| {}));
    let out = vec![
        key_change(
            &mut w,
            &thief_rotate,
            NOW + 1,
            KeyChange::OwnerConfirmationRequired,
        ),
        current_is(&w, 1, "after the thief's rotation"),
        code(&mut w, &by_thief(1), NOW + 2, WireErrorCode::BadSignature),
        key_change(
            &mut w,
            &thief_revoke,
            NOW + 3,
            KeyChange::OwnerConfirmationRequired,
        ),
        current_is(&w, 1, "after the thief's revocation"),
        code(&mut w, &by_thief(2), NOW + 4, WireErrorCode::BadSignature),
        key_change(&mut w, &genuine, NOW + 5, KeyChange::Installed),
        current_is(&w, ALICE_NEXT, "after the genuine rotation"),
        expect(
            w.recv
                .confirm_key_change(&tenant(2), &address(1), &kid(&thief)),
            |e| *e == NoPendingChange,
        ),
        code(&mut w, &by_thief(3), NOW + 6, WireErrorCode::BadSignature),
    ];
    all(out)
}

pub(crate) fn ca52_revoked_key_used() -> Outcome {
    let mut w = Wire::new();
    if let Err(fail) = rotate_genuinely(&mut w) {
        return fail;
    }
    let revoked = revocation(ALICE_NEXT, None, 220);
    let revoked_outcome = key_change(&mut w, &revoked, NOW + 2, KeyChange::Revoked);
    let by_revoked = sealed(&key(ALICE_NEXT), &message(BODY, vec![], 1, |_| {}));
    let by_previous = sealed(&w.alice, &message(BODY, vec![], 2, |_| {}));
    all([
        revoked_outcome,
        code(&mut w, &by_revoked, NOW + 3, WireErrorCode::BadSignature),
        code(&mut w, &by_previous, NOW + 3, WireErrorCode::BadSignature),
    ])
}
