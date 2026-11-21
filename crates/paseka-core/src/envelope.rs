//! Gate-to-gate envelopes: sealing by the sender and receiver verification (PROTOCOL §10.3).

use std::collections::BTreeMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use paseka_proto::envelope::{Envelope, Event, ReceiptStatus, WireErrorCode};
use paseka_proto::jws::{Compact, JwsError, MAX_TOKEN_BYTES, Typ};
use paseka_proto::{Address, EventId, Sha256, TenantId, UnixSecs};
use serde::Serialize;

use crate::hash::sha256;
use crate::mandate::{JtiBook, MandateInvalid, verify_received};
use crate::tenant::TenantMap;
use crate::token;

/// Allowed clock skew into the future.
pub const SKEW_SECS: u64 = 300;
/// Oldest accepted `iat`.
pub const MAX_AGE_SECS: u64 = 604_800;

/// Signs an envelope payload with the sender tenant key. Retries send the identical bytes.
///
/// # Panics
/// Never: envelope payloads always serialise.
pub fn seal<D: Serialize>(key: &SigningKey, env: &Envelope<D>) -> String {
    let payload = serde_json::to_vec(env).expect("envelope serialises");
    token::sign(key, Typ::Envelope, &payload)
}

/// Pairing state of a peer as the receiver knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// The local owner has not confirmed the pairing yet.
    PendingOwner,
    /// Active.
    Active,
}

/// An accepted envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// Addressed tenant.
    pub tenant: TenantId,
    /// The event; `None` for a duplicate already stored.
    pub event: Option<Event>,
    /// Receipt status.
    pub status: ReceiptStatus,
    /// SHA-256 of the compact JWS bytes.
    pub envelope_sha256: Sha256,
}

/// Receiver state: local tenants by address, paired peers with their recorded key, seen event
/// ids and mandate ids.
#[derive(Debug, Clone, Default)]
pub struct Receiver {
    tenants: BTreeMap<Address, TenantId>,
    peers: TenantMap<Address, (VerifyingKey, PeerState)>,
    seen: TenantMap<(Address, EventId), (Sha256, UnixSecs)>,
    jtis: JtiBook,
}

#[derive(serde::Deserialize)]
struct RawHead {
    v: u32,
    #[serde(rename = "type")]
    kind: String,
}

fn malformed(e: JwsError) -> WireErrorCode {
    match e {
        JwsError::TooLarge => WireErrorCode::TooLarge,
        _ => WireErrorCode::Malformed,
    }
}

impl Receiver {
    /// Registers a local tenant under its address.
    pub fn add_tenant(&mut self, tenant: TenantId) {
        self.tenants.insert(tenant.address(), tenant);
    }

    /// Records the peer `address` of `tenant` with its current `key`, in `state`.
    pub fn set_peer(
        &mut self,
        tenant: &TenantId,
        address: Address,
        key: VerifyingKey,
        state: PeerState,
    ) {
        self.peers.insert(tenant, address, (key, state));
    }

    /// Verifies and accepts one envelope in the order of PROTOCOL §10.3; the first failure
    /// determines the error code.
    ///
    /// # Errors
    /// The [`WireErrorCode`] the gate answers with.
    pub fn accept(&mut self, jws: &str, now: UnixSecs) -> Result<Accepted, WireErrorCode> {
        if jws.len() > MAX_TOKEN_BYTES {
            return Err(WireErrorCode::TooLarge);
        }
        let c = Compact::parse(jws).map_err(malformed)?;
        if c.header.typ != Typ::Envelope {
            return Err(WireErrorCode::Malformed);
        }
        let raw: RawHead =
            serde_json::from_slice(&c.payload).map_err(|_| WireErrorCode::Malformed)?;
        if raw.v != 1 || !matches!(raw.kind.as_str(), "message" | "pair.confirmed" | "unpair") {
            return Err(WireErrorCode::Unsupported);
        }
        let event = Event::parse(&c.payload).map_err(|_| WireErrorCode::Malformed)?;
        let head = event.head();
        let tenant = self
            .tenants
            .get(&head.aud)
            .cloned()
            .ok_or(WireErrorCode::NotPaired)?;
        let (key, state) = *self
            .peers
            .get(&tenant, &head.iss)
            .ok_or(WireErrorCode::NotPaired)?;
        token::verify(jws, Typ::Envelope, &key).map_err(|_| WireErrorCode::BadSignature)?;
        if head.iat > now.saturating_add(SKEW_SECS) {
            return Err(WireErrorCode::FromFuture);
        }
        if now.saturating_sub(head.iat) > MAX_AGE_SECS {
            return Err(WireErrorCode::Stale);
        }
        let digest = sha256(jws.as_bytes());
        self.seen
            .retain(|_, (_, at)| at.saturating_add(MAX_AGE_SECS + SKEW_SECS) > now);
        let id = (head.iss.clone(), head.id.clone());
        if let Some((stored, _)) = self.seen.get(&tenant, &id) {
            if *stored != digest {
                return Err(WireErrorCode::Conflict);
            }
            return Ok(Accepted {
                tenant,
                event: None,
                status: ReceiptStatus::Duplicate,
                envelope_sha256: digest,
            });
        }
        if state == PeerState::PendingOwner {
            return Err(WireErrorCode::PairingPending);
        }
        if let Event::Message(env) = &event {
            let m = verify_received(env, &key, &tenant, &self.jtis, now).map_err(|e| match e {
                MandateInvalid::Replay => WireErrorCode::MandateReplay,
                _ => WireErrorCode::MandateInvalid,
            })?;
            self.jtis.prune(now);
            self.jtis.record(&tenant, &m);
        }
        self.seen.insert(&tenant, id, (digest, now));
        Ok(Accepted {
            tenant,
            event: Some(event),
            status: ReceiptStatus::Accepted,
            envelope_sha256: digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use paseka_proto::envelope::MessageData;
    use serde_json::Value;

    use super::*;

    fn vectors() -> Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/fixtures/vectors/digests.json"
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn seed_key(v: &Value, name: &str) -> SigningKey {
        let hex = v["signing_keys"][name]["seed_hex"].as_str().unwrap();
        SigningKey::from_bytes(&Sha256::from_hex(hex).unwrap().0)
    }

    fn setup() -> (Receiver, String, Envelope<MessageData>, UnixSecs) {
        let v = vectors();
        let env: Envelope<MessageData> =
            serde_json::from_value(v["signed"]["envelope"]["payload"].clone()).unwrap();
        let (alice, carol) = (seed_key(&v, "alice"), seed_key(&v, "carol"));
        let jws = seal(&alice, &env);
        assert_eq!(jws, v["signed"]["envelope"]["compact"].as_str().unwrap());
        assert_eq!(
            sha256(jws.as_bytes()).to_hex(),
            v["signed"]["envelope"]["envelope_sha256"].as_str().unwrap()
        );
        let bob_tenant = TenantId::new("t_01JD0000000000000000000002").unwrap();
        let mut r = Receiver::default();
        r.add_tenant(bob_tenant.clone());
        r.set_peer(
            &bob_tenant,
            env.iss.clone(),
            alice.verifying_key(),
            PeerState::Active,
        );
        r.set_peer(
            &bob_tenant,
            Address::new("t_01JD0000000000000000000003").unwrap(),
            carol.verifying_key(),
            PeerState::Active,
        );
        let now = env.iat + 1;
        (r, jws, env, now)
    }

    #[test]
    fn the_vector_envelope_is_accepted_once_then_duplicate() {
        let (mut r, jws, _, now) = setup();
        assert_eq!(r.accept(&jws, now).unwrap().status, ReceiptStatus::Accepted);
        let again = r.accept(&jws, now).unwrap();
        assert_eq!(
            (again.status, again.event),
            (ReceiptStatus::Duplicate, None)
        );
    }

    #[test]
    fn stale_future_and_tampered_envelopes_are_refused() {
        let (mut r, jws, _, now) = setup();
        assert_eq!(
            r.accept(&jws, now + MAX_AGE_SECS + 10),
            Err(WireErrorCode::Stale)
        );
        assert_eq!(
            r.accept(&jws, now - SKEW_SECS - 10),
            Err(WireErrorCode::FromFuture)
        );
        let mut parts: Vec<&str> = jws.split('.').collect();
        let first = if parts[2].starts_with('A') { "B" } else { "A" };
        let sig = format!("{first}{}", &parts[2][1..]);
        parts[2] = &sig;
        assert_eq!(
            r.accept(&parts.join("."), now),
            Err(WireErrorCode::BadSignature)
        );
    }

    #[test]
    fn the_recipient_resolves_by_aud_and_the_kid_must_name_the_key_recorded_for_iss() {
        let v = vectors();
        let (mut r, _, env, now) = setup();
        let carol = seed_key(&v, "carol");
        assert_eq!(
            r.accept(&seal(&carol, &env), now),
            Err(WireErrorCode::BadSignature)
        );
        let mut unknown_sender = env.clone();
        unknown_sender.iss = Address::new("t_01JD0000000000000000000009").unwrap();
        assert_eq!(
            r.accept(&seal(&carol, &unknown_sender), now),
            Err(WireErrorCode::NotPaired)
        );
        let mut other_tenant = env;
        other_tenant.aud = Address::new("t_01JD0000000000000000000001").unwrap();
        assert_eq!(
            r.accept(&seal(&seed_key(&v, "alice"), &other_tenant), now),
            Err(WireErrorCode::NotPaired)
        );
    }
}
