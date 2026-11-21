//! Attacks on the gate-to-gate wire (SP-4, SP-12 to SP-15).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use paseka_core::envelope::{MAX_AGE_SECS, PeerState};
use paseka_core::mandate;
use paseka_core::pairing::{AcceptInvalid, Expected, verify_accept};
use paseka_core::token;
use paseka_proto::envelope::{ReceiptStatus, WireErrorCode};
use paseka_proto::jws::Typ;
use paseka_proto::pairing::{PairAccept, PairAcceptType, PairRequest, PairRequestType};
use paseka_proto::{Level, Sha256, V1};

use crate::world::{
    BODY, NOW, Wire, address, attachment, key, kid, mandate_for, message, nonce, pairing_id,
    sealed, tenant, thread,
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
    w.recv.set_peer(
        &tenant(2),
        address(3),
        carol.verifying_key(),
        PeerState::Active,
    );
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
    w.recv.add_tenant(tenant(3));
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
    w.recv.set_peer(
        &tenant(2),
        address(1),
        w.alice.verifying_key(),
        PeerState::PendingOwner,
    );
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
