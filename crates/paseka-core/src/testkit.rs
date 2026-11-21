//! Deterministic fixtures for unit tests.

use ed25519_dalek::SigningKey;
use paseka_proto::evidence::Channel;
use paseka_proto::{
    Address, DraftId, EventId, Nonce, PairingId, PeerHandle, RequestId, Sha256, TenantId, ThreadId,
};
use serde_json::Value;

use crate::channel::Channels;

/// The protocol test vectors, written by the generator in `vectors.rs`.
pub(crate) const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/fixtures/vectors/digests.json"
);

pub(crate) fn vectors() -> Value {
    serde_json::from_slice(&std::fs::read(VECTORS_PATH).unwrap()).unwrap()
}

/// The signing key of test party `name` in the vectors `v`.
pub(crate) fn seed_key(v: &Value, name: &str) -> SigningKey {
    let hex = v["signing_keys"][name]["seed_hex"].as_str().unwrap();
    SigningKey::from_bytes(&Sha256::from_hex(hex).unwrap().0)
}

pub(crate) fn ulid(prefix: &str, i: u8) -> String {
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

pub(crate) fn event(i: u8) -> EventId {
    EventId::new(ulid("e_", i)).unwrap()
}

pub(crate) fn pairing_id(i: u8) -> PairingId {
    PairingId::new(ulid("p_", i)).unwrap()
}

pub(crate) fn peer(s: &str) -> PeerHandle {
    PeerHandle::new(s).unwrap()
}

pub(crate) fn nonce(i: u8) -> Nonce {
    Nonce::new(format!("nonce{i:0>16}A")).unwrap()
}

/// The MVP approval channels: button, Mini App, Mini App with PIN.
pub(crate) fn mvp_channels() -> Channels {
    Channels::new(vec![
        Channel::TelegramButton,
        Channel::TelegramMiniApp,
        Channel::TelegramMiniAppPin,
    ])
    .unwrap()
}

pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
