//! Attacks on the gate-to-gate wire (SP-4, SP-12 to SP-15).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use paseka_core::envelope::{MAX_AGE_SECS, PeerState};
use paseka_core::token;
use paseka_proto::envelope::{ReceiptStatus, WireErrorCode};
use paseka_proto::jws::Typ;
use paseka_proto::{Level, Sha256};

use crate::world::{BODY, NOW, Wire, attachment, key, kid, message, sealed, tenant, thread};
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
    let env = message(BODY, vec![], 1, |_| {});
    let stranger = key(9);
    let by_stranger = sealed(&stranger, &env);
    let payload = serde_json::to_vec(&env).expect("serialises");
    let alg_none = {
        let h = format!(
            r#"{{"alg":"none","kid":"{}","typ":"paseka-envelope+jwt"}}"#,
            env.iss
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
            env.iss
        );
        format!(
            "{}.{}.AAAA",
            URL_SAFE_NO_PAD.encode(h),
            URL_SAFE_NO_PAD.encode(&payload)
        )
    };
    let kid_mismatch = {
        let mut other = env.clone();
        other.iss = kid(&stranger);
        sealed(&w.alice, &other)
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
        code(&mut w, &by_stranger, NOW, WireErrorCode::NotPaired),
        code(&mut w, &alg_none, NOW, WireErrorCode::Malformed),
        code(&mut w, &alg_hs256, NOW, WireErrorCode::Malformed),
        code(&mut w, &kid_mismatch, NOW, WireErrorCode::NotPaired),
        code(&mut w, &bad_sig, NOW, WireErrorCode::BadSignature),
    ])
}

pub(crate) fn ca32_cross_tenant_envelope() -> Outcome {
    let mut w = Wire::new();
    let carol = key(3);
    w.recv.add_tenant(kid(&carol), tenant(3));
    let mut env = message(BODY, vec![], 1, |_| {});
    env.aud = kid(&carol);
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
        message(BODY, vec![], 2, |m| m.to = kid(&key(9))),
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
    w.recv
        .set_peer(&tenant(2), w.alice.verifying_key(), PeerState::PendingOwner);
    let jws = sealed(&w.alice, &message(BODY, vec![], 1, |_| {}));
    code(&mut w, &jws, NOW, WireErrorCode::PairingPending)
}
