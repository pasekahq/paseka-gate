//! Signing and verifying JWS compact tokens with ed25519 keys.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use paseka_proto::jws::{self, ALG_EDDSA, Compact, Header};
use paseka_proto::{Level, TenantId};

/// Why a token was refused before its payload was looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    /// Not a well-formed compact token.
    Malformed,
    /// `alg` is not `EdDSA`.
    BadAlg,
    /// `typ` is not the expected one.
    WrongTyp,
    /// `kid` is not a trusted key.
    UnknownKey,
    /// Signature does not verify.
    BadSignature,
}

/// Signs `payload` as a compact token.
pub fn sign(key: &SigningKey, kid: &str, typ: &str, payload: &[u8]) -> String {
    let header = Header {
        alg: ALG_EDDSA.into(),
        typ: typ.into(),
        kid: kid.into(),
    };
    let input = jws::signing_input(&header, payload);
    let sig = key.sign(input.as_bytes());
    jws::assemble(&input, &sig.to_bytes())
}

/// Parses `token`, checks `alg`/`typ`, looks up `kid` and verifies the signature strictly.
///
/// # Errors
/// [`TokenError`] on any failed step.
pub fn verify<'k, K>(
    token: &str,
    typ: &str,
    lookup: impl FnOnce(&str) -> Option<(&'k VerifyingKey, K)>,
) -> Result<(K, Vec<u8>), TokenError> {
    let c = Compact::parse(token).map_err(|_| TokenError::Malformed)?;
    if c.header.alg != ALG_EDDSA {
        return Err(TokenError::BadAlg);
    }
    if c.header.typ != typ {
        return Err(TokenError::WrongTyp);
    }
    let (vk, meta) = lookup(&c.header.kid).ok_or(TokenError::UnknownKey)?;
    let sig = Signature::from_slice(&c.signature).map_err(|_| TokenError::BadSignature)?;
    vk.verify_strict(&c.signing_input, &sig)
        .map_err(|_| TokenError::BadSignature)?;
    Ok((meta, c.payload))
}

/// Key id of a verifying key: its 32 bytes in base64url.
pub fn kid_of(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(key.as_bytes())
}

/// A key allowed to sign mandates for one tenant up to a maximum level.
#[derive(Debug, Clone)]
pub struct Approver {
    /// Tenant the key may consent for.
    pub tenant: TenantId,
    /// Highest level this key can attest.
    pub max_level: Level,
    /// Public key.
    pub key: VerifyingKey,
}

/// Trusted approver keys by `kid`. Lives in the gate; the agent can neither read nor change it.
#[derive(Debug, Clone, Default)]
pub struct ApproverRing {
    by_kid: BTreeMap<String, Approver>,
}

impl ApproverRing {
    /// Adds `approver`; its kid is [`kid_of`] its key.
    pub fn insert(&mut self, approver: Approver) {
        self.by_kid.insert(kid_of(&approver.key), approver);
    }

    /// Looks up an approver by kid.
    pub fn get(&self, kid: &str) -> Option<&Approver> {
        self.by_kid.get(kid)
    }
}
