//! Pairing (PROTOCOL §11): the invitee's check of a pair accept against the pair URI.

use ed25519_dalek::VerifyingKey;
use paseka_proto::jws::Typ;
use paseka_proto::pairing::PairAccept;
use paseka_proto::{Address, KeyId};

use crate::hash::sha256;
use crate::token::{self, TokenError};

/// What the invitee expects of the accept: the inviter named by the pair URI and its own request.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// Inviter address, `a` of the pair URI.
    pub inviter: &'a Address,
    /// Inviter key, `k` of the pair URI.
    pub inviter_key: &'a KeyId,
    /// Invitee address, `iss` of the request.
    pub invitee: &'a Address,
    /// The pair request sent, as compact JWS.
    pub request: &'a str,
}

/// Why a pair accept was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptInvalid {
    /// JWS checks failed: `typ`, a `kid` other than the URI key, or the signature.
    Token(TokenError),
    /// Payload is not a pair accept.
    Payload,
    /// `iss` or `key` differ from the pair URI.
    Inviter,
    /// `aud` is not the invitee.
    Audience,
    /// `request_sha256` does not hash the request sent.
    Request,
}

/// Verifies a pair accept (PROTOCOL §11 step 5). On success the invitee pins the returned key
/// for `inviter`.
///
/// # Errors
/// [`AcceptInvalid`] for the first failed check.
pub fn verify_accept(
    accept: &str,
    want: &Expected<'_>,
) -> Result<(PairAccept, VerifyingKey), AcceptInvalid> {
    let key = token::key_from_id(want.inviter_key).map_err(AcceptInvalid::Token)?;
    let payload = token::verify(accept, Typ::Pair, &key).map_err(AcceptInvalid::Token)?;
    let a: PairAccept = serde_json::from_slice(&payload).map_err(|_| AcceptInvalid::Payload)?;
    if &a.iss != want.inviter || &a.key != want.inviter_key {
        return Err(AcceptInvalid::Inviter);
    }
    if &a.aud != want.invitee {
        return Err(AcceptInvalid::Audience);
    }
    if a.request_sha256 != sha256(want.request.as_bytes()) {
        return Err(AcceptInvalid::Request);
    }
    Ok((a, key))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use serde_json::Value;

    use super::*;

    fn vectors() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/fixtures/vectors/digests.json"
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn party(v: &Value, name: &str) -> (SigningKey, KeyId, Address) {
        let k = &v["signing_keys"][name];
        let seed = paseka_proto::Sha256::from_hex(k["seed_hex"].as_str().unwrap()).unwrap();
        (
            SigningKey::from_bytes(&seed.0),
            serde_json::from_value(k["key_id"].clone()).unwrap(),
            serde_json::from_value(k["address"].clone()).unwrap(),
        )
    }

    #[test]
    fn the_vector_accept_binds_the_uri_address_and_key() {
        let v = vectors();
        let (alice, alice_kid, alice_addr) = party(&v, "alice");
        let (_, _, bob_addr) = party(&v, "bob");
        let (carol, carol_kid, carol_addr) = party(&v, "carol");
        let signed = &v["signed"];
        let request = signed["pair_request"]["compact"].as_str().unwrap();
        let accept = signed["pair_accept"]["compact"].as_str().unwrap();
        let want = Expected {
            inviter: &alice_addr,
            inviter_key: &alice_kid,
            invitee: &bob_addr,
            request,
        };
        let (a, key) = verify_accept(accept, &want).unwrap();
        assert_eq!((a.iss, key), (alice_addr.clone(), alice.verifying_key()));

        let payload: PairAccept =
            serde_json::from_value(signed["pair_accept"]["payload"].clone()).unwrap();
        let sign = |k: &SigningKey, p: &PairAccept| {
            token::sign(k, Typ::Pair, &serde_json::to_vec(p).unwrap())
        };
        let mut by_carol = payload.clone();
        by_carol.key = carol_kid;
        assert_eq!(
            verify_accept(&sign(&carol, &by_carol), &want),
            Err(AcceptInvalid::Token(TokenError::WrongKid))
        );
        let mut wrong_iss = payload.clone();
        wrong_iss.iss = carol_addr;
        assert_eq!(
            verify_accept(&sign(&alice, &wrong_iss), &want),
            Err(AcceptInvalid::Inviter)
        );
        let mut wrong_aud = payload;
        wrong_aud.aud = alice_addr.clone();
        assert_eq!(
            verify_accept(&sign(&alice, &wrong_aud), &want),
            Err(AcceptInvalid::Audience)
        );
        let other_request = Expected {
            request: signed["receipt"]["compact"].as_str().unwrap(),
            ..want
        };
        assert_eq!(
            verify_accept(accept, &other_request),
            Err(AcceptInvalid::Request)
        );
    }
}
