//! Gate-to-gate envelopes: sealing by the sender and receiver verification (PROTOCOL §10.3).

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use paseka_proto::envelope::{Envelope, Event, ReceiptStatus, WireErrorCode};
use paseka_proto::jws::{Compact, JwsError, MAX_TOKEN_BYTES, Typ};
use paseka_proto::{Address, EventId, KeyId, Sha256, TenantId, UnixSecs};
use serde::Serialize;

use crate::hash::sha256;
use crate::mandate::{JtiBook, MandateInvalid, verify_received};
use crate::peer::{KeyChange, KeyChangeRefused, NoPendingChange, PeerKeys};
use crate::tenant::TenantMap;
use crate::token;

/// Allowed clock skew into the future of envelope, mandate and pairing times (PROTOCOL §14).
pub const SKEW_SECS: u64 = 300;
/// Envelope window: the oldest accepted `iat` is this far before `now` (PROTOCOL §10.3, §14).
pub const MAX_AGE_SECS: u64 = 604_800;
/// Retry horizon: the sender attempts a delivery until this long after `iat` (PROTOCOL §10.4,
/// §14).
pub const RETRY_HORIZON_SECS: u64 = 72 * 3600;

/// Whether the sender may still attempt delivery of an envelope created at `iat`; once not, the
/// delivery is `failed`.
pub fn retry_allowed(iat: UnixSecs, now: UnixSecs) -> bool {
    now < iat.saturating_add(RETRY_HORIZON_SECS)
}

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

/// Why a peer cannot be recorded (PROTOCOL §11 step 4); answered as `conflict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerConflict {
    /// The address is one of this gate's own tenants.
    OwnTenant,
    /// The address is already recorded with another current key.
    OtherKey,
}

/// A tenant address that a tenant of this gate already records as a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressIsPeer;

#[derive(Debug, Clone)]
struct Peer {
    keys: PeerKeys,
    state: PeerState,
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
    /// What a stored `key.rotate` or `key.revoke` event did to the peer record; `None` for
    /// other events.
    pub key_change: Option<KeyChange>,
}

/// Receiver state: local tenants by address, paired peers with their key records, seen event ids
/// and mandate ids.
#[derive(Debug, Clone, Default)]
pub struct Receiver {
    tenants: BTreeMap<Address, TenantId>,
    peers: TenantMap<Address, Peer>,
    /// Every peer address with the tenants that recorded it, so no tenant takes a peer's address.
    peer_addresses: BTreeMap<Address, BTreeSet<TenantId>>,
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

/// §10.3 steps 1 and 6 up to the parse of `data`: size, syntax, `typ`, version and known type.
fn parse_event(jws: &str) -> Result<Event, WireErrorCode> {
    const KNOWN: [&str; 5] = [
        "message",
        "pair.confirmed",
        "unpair",
        "key.rotate",
        "key.revoke",
    ];
    if jws.len() > MAX_TOKEN_BYTES {
        return Err(WireErrorCode::TooLarge);
    }
    let c = Compact::parse(jws).map_err(malformed)?;
    if c.header.typ != Typ::Envelope {
        return Err(WireErrorCode::Malformed);
    }
    let raw: RawHead = serde_json::from_slice(&c.payload).map_err(|_| WireErrorCode::Malformed)?;
    if raw.v != 1 || !KNOWN.contains(&raw.kind.as_str()) {
        return Err(WireErrorCode::Unsupported);
    }
    Event::parse(&c.payload).map_err(|_| WireErrorCode::Malformed)
}

impl Receiver {
    /// Registers a local tenant under its address.
    ///
    /// # Errors
    /// [`AddressIsPeer`] when a tenant of this gate already records the address as a peer.
    pub fn add_tenant(&mut self, tenant: TenantId) -> Result<(), AddressIsPeer> {
        let address = tenant.address();
        if self.peer_addresses.contains_key(&address) {
            return Err(AddressIsPeer);
        }
        self.tenants.insert(address, tenant);
        Ok(())
    }

    /// Records the peer `address` of `tenant` with the key record pairing made, in `state`. An
    /// address already recorded with the same current key keeps its record and takes `state`.
    ///
    /// # Errors
    /// [`PeerConflict`] for one of this gate's tenants or an address recorded with another key.
    pub fn add_peer(
        &mut self,
        tenant: &TenantId,
        address: Address,
        keys: PeerKeys,
        state: PeerState,
    ) -> Result<(), PeerConflict> {
        if self.tenants.contains_key(&address) {
            return Err(PeerConflict::OwnTenant);
        }
        if let Some(peer) = self.peers.get_mut(tenant, &address) {
            if peer.keys.current() != keys.current() {
                return Err(PeerConflict::OtherKey);
            }
            peer.state = state;
            return Ok(());
        }
        self.peer_addresses
            .entry(address.clone())
            .or_default()
            .insert(tenant.clone());
        self.peers.insert(tenant, address, Peer { keys, state });
        Ok(())
    }

    /// Makes the pending key change of the peer `address` of `tenant` current, once the owner of
    /// `tenant` confirmed `new_key` through the consent path (PROTOCOL §10.8).
    ///
    /// # Errors
    /// [`NoPendingChange`] for an unknown peer or no pending change naming `new_key`.
    pub fn confirm_key_change(
        &mut self,
        tenant: &TenantId,
        address: &Address,
        new_key: &KeyId,
    ) -> Result<(), NoPendingChange> {
        self.peers
            .get_mut(tenant, address)
            .ok_or(NoPendingChange)?
            .keys
            .confirm_change(new_key)
    }

    /// The key record of the peer `address` of `tenant`.
    pub fn peer_keys(&self, tenant: &TenantId, address: &Address) -> Option<&PeerKeys> {
        self.peers.get(tenant, address).map(|p| &p.keys)
    }

    /// Verifies and accepts one envelope in the order of PROTOCOL §10.3; the first failure
    /// determines the error code. A `key.rotate` or `key.revoke` event updates the peer record
    /// (§10.6, §10.7).
    ///
    /// # Errors
    /// The [`WireErrorCode`] the gate answers with.
    ///
    /// # Panics
    /// Never: the peer of a key event was looked up before.
    pub fn accept(&mut self, jws: &str, now: UnixSecs) -> Result<Accepted, WireErrorCode> {
        let event = parse_event(jws)?;
        let head = event.head();
        let tenant = self
            .tenants
            .get(&head.aud)
            .cloned()
            .ok_or(WireErrorCode::NotPaired)?;
        let peer = self
            .peers
            .get(&tenant, &head.iss)
            .cloned()
            .ok_or(WireErrorCode::NotPaired)?;
        let key_event = matches!(event, Event::KeyRotate(_) | Event::KeyRevoke(_));
        let verified = if key_event {
            peer.keys.verify_key_event(jws).is_ok()
        } else {
            peer.keys.verify(jws, Typ::Envelope, now).is_ok()
        };
        if !verified {
            return Err(WireErrorCode::BadSignature);
        }
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
                key_change: None,
            });
        }
        if peer.state == PeerState::PendingOwner {
            return Err(WireErrorCode::PairingPending);
        }
        let mut key_change = None;
        match &event {
            Event::Message(env) => {
                let m = verify_received(env, &peer.keys, &tenant, &self.jtis, now).map_err(
                    |e| match e {
                        MandateInvalid::Replay => WireErrorCode::MandateReplay,
                        _ => WireErrorCode::MandateInvalid,
                    },
                )?;
                self.jtis.prune(now);
                self.jtis.record(&tenant, &m);
            }
            Event::KeyRotate(_) | Event::KeyRevoke(_) => {
                let keys = &mut self
                    .peers
                    .get_mut(&tenant, &head.iss)
                    .expect("the peer was looked up above")
                    .keys;
                let changed = if matches!(event, Event::KeyRotate(_)) {
                    keys.rotate(jws)
                } else {
                    keys.revoke(jws)
                };
                key_change = Some(changed.map_err(|e| match e {
                    KeyChangeRefused::Payload => WireErrorCode::Malformed,
                    KeyChangeRefused::NotCurrentKey(_) | KeyChangeRefused::Proof => {
                        WireErrorCode::BadSignature
                    }
                })?);
            }
            Event::PairConfirmed(_) | Event::Unpair(_) => {}
        }
        self.seen.insert(&tenant, id, (digest, now));
        Ok(Accepted {
            tenant,
            event: Some(event),
            status: ReceiptStatus::Accepted,
            envelope_sha256: digest,
            key_change,
        })
    }
}

#[cfg(test)]
mod tests {
    use paseka_proto::V1;
    use paseka_proto::envelope::{
        EventType, KeyRevokeData, KeyRotateData, MessageData, UnpairData,
    };
    use paseka_proto::pairing::PairAccept;

    use super::*;
    use crate::peer::{key_revoke_data, key_sha256};
    use crate::testkit::{address, event, key, seed_key, tenant, vectors};
    use crate::token::key_id;

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
        r.add_tenant(bob_tenant.clone()).unwrap();
        r.add_peer(
            &bob_tenant,
            env.iss.clone(),
            PeerKeys::paired(alice.verifying_key(), None),
            PeerState::Active,
        )
        .unwrap();
        r.add_peer(
            &bob_tenant,
            Address::new("t_01JD0000000000000000000003").unwrap(),
            PeerKeys::paired(carol.verifying_key(), None),
            PeerState::Active,
        )
        .unwrap();
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
    fn the_envelope_window_and_the_skew_are_inclusive() {
        let (_, _, env, _) = setup();
        let cases = [
            (env.iat + MAX_AGE_SECS, Ok(ReceiptStatus::Accepted)),
            (env.iat + MAX_AGE_SECS + 1, Err(WireErrorCode::Stale)),
            (env.iat - SKEW_SECS, Ok(ReceiptStatus::Accepted)),
            (env.iat - SKEW_SECS - 1, Err(WireErrorCode::FromFuture)),
        ];
        for (now, want) in cases {
            let (mut r, jws, _, _) = setup();
            assert_eq!(r.accept(&jws, now).map(|a| a.status), want, "now {now}");
        }
    }

    #[test]
    fn delivery_is_retried_until_the_horizon() {
        assert!(retry_allowed(IAT, IAT + RETRY_HORIZON_SECS - 1));
        assert!(!retry_allowed(IAT, IAT + RETRY_HORIZON_SECS));
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

    #[test]
    fn a_recorded_address_keeps_its_key_and_an_own_tenant_address_is_no_peer() {
        let v = vectors();
        let (mut r, jws, _, now) = setup();
        let (alice, carol) = (seed_key(&v, "alice"), seed_key(&v, "carol"));
        let paired = |k: &SigningKey| PeerKeys::paired(k.verifying_key(), None);
        assert_eq!(
            r.add_peer(&tenant(2), address(1), paired(&carol), PeerState::Active),
            Err(PeerConflict::OtherKey)
        );
        assert_eq!(
            r.add_peer(&tenant(2), address(2), paired(&carol), PeerState::Active),
            Err(PeerConflict::OwnTenant)
        );
        assert_eq!(r.peer_keys(&tenant(2), &address(1)), Some(&paired(&alice)));
        r.add_peer(
            &tenant(2),
            address(1),
            paired(&alice),
            PeerState::PendingOwner,
        )
        .unwrap();
        assert_eq!(r.accept(&jws, now), Err(WireErrorCode::PairingPending));
    }

    #[test]
    fn the_vector_rotation_is_auto_accepted_under_the_vector_accept_commitment() {
        let v = vectors();
        let signed = &v["signed"];
        let accept: PairAccept =
            serde_json::from_value(signed["pair_accept"]["payload"].clone()).unwrap();
        let rotate: Envelope<KeyRotateData> =
            serde_json::from_value(signed["key_rotate"]["payload"].clone()).unwrap();
        let alice = seed_key(&v, "alice");
        let jws = seal(&alice, &rotate);
        assert_eq!(jws, signed["key_rotate"]["compact"].as_str().unwrap());
        let mut r = Receiver::default();
        r.add_tenant(tenant(2)).unwrap();
        let keys = PeerKeys::paired(alice.verifying_key(), accept.next_key_sha256);
        r.add_peer(&tenant(2), accept.iss.clone(), keys, PeerState::Active)
            .unwrap();
        let got = r.accept(&jws, rotate.iat + 1).unwrap();
        assert_eq!(got.key_change, Some(KeyChange::Installed));
        let keys = r.peer_keys(&tenant(2), &accept.iss).unwrap();
        assert_eq!(*keys.current(), seed_key(&v, "alice-2").verifying_key());
        assert_eq!(
            keys.previous(),
            Some((alice.verifying_key(), rotate.data.previous_valid_until))
        );
    }

    #[test]
    fn the_vector_revocation_installs_the_committed_replacement_without_grace() {
        let v = vectors();
        let signed = &v["signed"];
        let accept: PairAccept =
            serde_json::from_value(signed["pair_accept"]["payload"].clone()).unwrap();
        let revoke: Envelope<KeyRevokeData> =
            serde_json::from_value(signed["key_revoke"]["payload"].clone()).unwrap();
        let alice = seed_key(&v, "alice");
        let jws = seal(&alice, &revoke);
        assert_eq!(jws, signed["key_revoke"]["compact"].as_str().unwrap());
        let mut r = Receiver::default();
        r.add_tenant(tenant(2)).unwrap();
        let keys = PeerKeys::paired(alice.verifying_key(), accept.next_key_sha256);
        r.add_peer(&tenant(2), accept.iss.clone(), keys, PeerState::Active)
            .unwrap();
        let got = r.accept(&jws, revoke.iat + 1).unwrap();
        assert_eq!(got.key_change, Some(KeyChange::Installed));
        let keys = r.peer_keys(&tenant(2), &accept.iss).unwrap();
        assert_eq!(*keys.current(), seed_key(&v, "alice-2").verifying_key());
        assert_eq!(keys.previous(), None);
    }

    /// bob's gate with alice (key 1, committed to key 2) as an active peer.
    fn receiver_of_alice() -> Receiver {
        let mut r = Receiver::default();
        r.add_tenant(tenant(2)).unwrap();
        let keys = PeerKeys::paired(
            key(1).verifying_key(),
            Some(key_sha256(&key(2).verifying_key())),
        );
        r.add_peer(&tenant(2), address(1), keys, PeerState::Active)
            .unwrap();
        r
    }

    const IAT: UnixSecs = 1_794_268_830;

    fn from_alice<D>(id: u8, kind: EventType, data: D) -> Envelope<D> {
        Envelope {
            v: V1,
            iss: address(1),
            aud: address(2),
            id: event(id),
            kind,
            iat: IAT,
            data,
        }
    }

    fn unpair(id: u8) -> Envelope<UnpairData> {
        from_alice(
            id,
            EventType::Unpair,
            UnpairData {
                reason: "bye".into(),
            },
        )
    }

    #[test]
    fn a_revoked_key_signs_nothing_but_key_events_until_the_owner_confirms_a_replacement() {
        let mut r = receiver_of_alice();
        let revoke = |id: u8, replacement: Option<(&SigningKey, Sha256)>| {
            let data = key_revoke_data(&address(1), &key(1).verifying_key(), replacement);
            seal(&key(1), &from_alice(id, EventType::KeyRevoke, data))
        };
        let got = r.accept(&revoke(1, None), IAT).unwrap();
        assert_eq!(got.key_change, Some(KeyChange::Revoked));
        assert_eq!(
            r.accept(&seal(&key(1), &unpair(2)), IAT),
            Err(WireErrorCode::BadSignature)
        );

        let next = key_sha256(&key(3).verifying_key());
        let got = r.accept(&revoke(3, Some((&key(9), next))), IAT).unwrap();
        assert_eq!(got.key_change, Some(KeyChange::OwnerConfirmationRequired));
        assert_eq!(
            r.accept(&seal(&key(9), &unpair(4)), IAT),
            Err(WireErrorCode::BadSignature)
        );
        let replacement = key_id(&key(9).verifying_key());
        assert_eq!(
            r.confirm_key_change(&tenant(3), &address(1), &replacement),
            Err(NoPendingChange)
        );
        r.confirm_key_change(&tenant(2), &address(1), &replacement)
            .unwrap();
        assert_eq!(
            r.accept(&seal(&key(9), &unpair(5)), IAT).map(|a| a.status),
            Ok(ReceiptStatus::Accepted)
        );
        assert_eq!(
            r.accept(&seal(&key(1), &unpair(6)), IAT),
            Err(WireErrorCode::BadSignature)
        );
    }

    #[test]
    fn a_key_event_with_a_bad_replacement_is_refused_with_the_record_unchanged() {
        let mut r = receiver_of_alice();
        let mut data = key_revoke_data(
            &address(1),
            &key(1).verifying_key(),
            Some((&key(2), key_sha256(&key(3).verifying_key()))),
        );
        data.replacement.as_mut().unwrap().proof = key_revoke_data(
            &address(1),
            &key(1).verifying_key(),
            Some((&key(9), key_sha256(&key(3).verifying_key()))),
        )
        .replacement
        .unwrap()
        .proof;
        let before = r.peer_keys(&tenant(2), &address(1)).cloned();
        let jws = seal(&key(1), &from_alice(1, EventType::KeyRevoke, data));
        assert_eq!(r.accept(&jws, IAT), Err(WireErrorCode::BadSignature));
        assert_eq!(r.peer_keys(&tenant(2), &address(1)).cloned(), before);
    }

    #[test]
    fn a_tenant_cannot_take_an_address_recorded_as_a_peer() {
        let mut r = receiver_of_alice();
        assert_eq!(r.add_tenant(tenant(1)), Err(AddressIsPeer));
        assert_eq!(
            r.accept(&seal(&key(1), &unpair(1)), IAT).map(|a| a.tenant),
            Ok(tenant(2))
        );
        assert_eq!(r.add_tenant(tenant(3)), Ok(()));
    }
}
