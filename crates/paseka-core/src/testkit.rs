//! Deterministic fixtures for unit tests.

use ed25519_dalek::SigningKey;
use paseka_proto::{Nonce, PeerId, TenantId};

pub(crate) fn tenant(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}

pub(crate) fn peer(s: &str) -> PeerId {
    PeerId::new(s).unwrap()
}

pub(crate) fn nonce(i: u8) -> Nonce {
    Nonce::new(format!("nonce-{i:0>20}")).unwrap()
}

pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
