//! Deterministic fixtures for unit tests.

use ed25519_dalek::SigningKey;
use paseka_proto::{Address, DraftId, Nonce, PeerHandle, RequestId, TenantId, ThreadId};

fn ulid(prefix: &str, i: u8) -> String {
    format!("{prefix}01JD{i:0>22}")
}

pub(crate) fn tenant(i: u8) -> TenantId {
    TenantId::new(ulid("t_", i)).unwrap()
}

pub(crate) fn address(i: u8) -> Address {
    tenant(i).address()
}

pub(crate) fn draft_id(i: u8) -> DraftId {
    DraftId::new(ulid("d_", i)).unwrap()
}

pub(crate) fn request_id(i: u8) -> RequestId {
    RequestId::new(ulid("r_", i)).unwrap()
}

pub(crate) fn thread(i: u8) -> ThreadId {
    ThreadId::new(ulid("th_", i)).unwrap()
}

pub(crate) fn peer(s: &str) -> PeerHandle {
    PeerHandle::new(s).unwrap()
}

pub(crate) fn nonce(i: u8) -> Nonce {
    Nonce::new(format!("nonce{i:0>16}A")).unwrap()
}

pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
