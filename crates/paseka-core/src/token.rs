//! Signing and verifying JWS compact tokens with the tenant's Ed25519 key (PROTOCOL §8.1).
//! The verifier takes the key only from local state, never from the token.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use paseka_proto::KeyId;
use paseka_proto::jws::{self, Alg, Compact, Header, JwsError, Typ};

/// Why a token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Size, shape, base64 or header invalid (`alg` other than `EdDSA` included).
    Malformed(JwsError),
    /// `typ` differs from the expected type.
    WrongTyp,
    /// `kid` does not name the expected key.
    WrongKid,
    /// Signature does not verify.
    BadSignature,
}

impl From<JwsError> for TokenError {
    fn from(e: JwsError) -> Self {
        Self::Malformed(e)
    }
}

/// Key id of a verifying key: `ed25519:` + b64u of its 32 bytes.
///
/// # Panics
/// Never: the format always validates.
pub fn key_id(key: &VerifyingKey) -> KeyId {
    KeyId::new(format!(
        "ed25519:{}",
        URL_SAFE_NO_PAD.encode(key.as_bytes())
    ))
    .expect("encoded key is a valid key id")
}

/// The verifying key named by a key id: the `key` of a pair request or the `k` of a pair URI
/// (PROTOCOL §11).
///
/// # Errors
/// [`TokenError::BadSignature`] when the id does not decode to a valid Ed25519 point.
pub fn key_from_id(id: &KeyId) -> Result<VerifyingKey, TokenError> {
    let raw = id.as_str().trim_start_matches("ed25519:");
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(raw)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(TokenError::BadSignature)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| TokenError::BadSignature)
}

/// Signs `payload` as a compact JWS of type `typ` with `key`.
pub fn sign(key: &SigningKey, typ: Typ, payload: &[u8]) -> String {
    let header = Header {
        alg: Alg::EdDSA,
        kid: key_id(&key.verifying_key()),
        typ,
    };
    let input = jws::signing_input(&header, payload);
    let sig = key.sign(input.as_bytes());
    jws::assemble(&input, &sig.to_bytes())
}

/// Signs a mandate payload as an SD-JWT with zero disclosures.
pub fn sign_mandate(key: &SigningKey, payload: &[u8]) -> String {
    format!("{}~", sign(key, Typ::Mandate, payload))
}

fn check(
    c: &Compact,
    typ: Typ,
    resolve: impl FnOnce(&KeyId) -> Option<VerifyingKey>,
) -> Result<Vec<u8>, TokenError> {
    if c.header.typ != typ {
        return Err(TokenError::WrongTyp);
    }
    let key = resolve(&c.header.kid).ok_or(TokenError::WrongKid)?;
    if c.header.kid != key_id(&key) {
        return Err(TokenError::WrongKid);
    }
    let sig = Signature::from_slice(&c.signature).map_err(|_| TokenError::BadSignature)?;
    key.verify_strict(&c.signing_input, &sig)
        .map_err(|_| TokenError::BadSignature)?;
    Ok(c.payload.clone())
}

/// Verifies a compact JWS of type `typ` whose `kid` names `key` and whose signature `key` makes.
///
/// # Errors
/// [`TokenError`] on any failed check.
pub fn verify(token: &str, typ: Typ, key: &VerifyingKey) -> Result<Vec<u8>, TokenError> {
    verify_with(token, typ, |kid| (*kid == key_id(key)).then_some(*key))
}

/// Verifies a compact JWS of type `typ` with the key `resolve` returns for its `kid`; `None`
/// refuses it as [`TokenError::WrongKid`].
///
/// # Errors
/// [`TokenError`] on any failed check.
pub fn verify_with(
    token: &str,
    typ: Typ,
    resolve: impl FnOnce(&KeyId) -> Option<VerifyingKey>,
) -> Result<Vec<u8>, TokenError> {
    check(&Compact::parse(token)?, typ, resolve)
}

/// Verifies a mandate SD-JWT (zero disclosures) with the key `resolve` returns for its `kid`.
///
/// # Errors
/// [`TokenError`] on any failed check.
pub fn verify_mandate_with(
    token: &str,
    resolve: impl FnOnce(&KeyId) -> Option<VerifyingKey>,
) -> Result<Vec<u8>, TokenError> {
    check(&Compact::parse_sd_jwt(token)?, Typ::Mandate, resolve)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::key;

    #[test]
    fn a_token_verifies_only_with_its_type_and_the_key_its_kid_names() {
        let (alice, bob) = (key(1), key(2));
        let kid = key_id(&alice.verifying_key());
        let t = sign(&alice, Typ::Envelope, b"{}");
        assert_eq!(
            verify(&t, Typ::Envelope, &alice.verifying_key()),
            Ok(b"{}".to_vec())
        );
        assert_eq!(
            verify(&t, Typ::Receipt, &alice.verifying_key()),
            Err(TokenError::WrongTyp)
        );
        assert_eq!(
            verify(&t, Typ::Envelope, &bob.verifying_key()),
            Err(TokenError::WrongKid)
        );
        assert_eq!(key_from_id(&kid), Ok(alice.verifying_key()));
    }
}
