//! Peer key records: rotation, revocation and owner-confirmed key change (PROTOCOL §2,
//! §10.6 to §10.8; ADR 0013).

use std::ops::RangeInclusive;

use ed25519_dalek::{SigningKey, VerifyingKey};
use paseka_proto::envelope::{
    Envelope, KeyProof, KeyReplacement, KeyReplacementProof, KeyRevokeData, KeyRotateData,
};
use paseka_proto::jws::Typ;
use paseka_proto::{Address, KeyId, Sha256, UnixSecs, V1};

use crate::hash::sha256;
use crate::token::{self, TokenError, key_from_id, key_id};

const DAY_SECS: u64 = 86_400;

/// Owner setting range of the grace of a replaced key, in days. Its end caps the grace a
/// receiver grants whatever the sender asks.
pub const GRACE_DAYS: RangeInclusive<u64> = 1..=30;
/// Default grace of a replaced key, in days.
pub const DEFAULT_GRACE_DAYS: u64 = 7;
const MAX_GRACE_SECS: u64 = *GRACE_DAYS.end() * DAY_SECS;

/// A grace outside [`GRACE_DAYS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraceOutOfRange;

/// How long a sender keeps its replaced key valid after a rotation: whole days in [`GRACE_DAYS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grace {
    days: u64,
}

impl Grace {
    /// A grace of `days`.
    ///
    /// # Errors
    /// [`GraceOutOfRange`] outside [`GRACE_DAYS`].
    pub fn days(days: u64) -> Result<Self, GraceOutOfRange> {
        if GRACE_DAYS.contains(&days) {
            Ok(Self { days })
        } else {
            Err(GraceOutOfRange)
        }
    }

    /// `previous_valid_until` of a rotation created at `iat`.
    pub fn previous_valid_until(self, iat: UnixSecs) -> UnixSecs {
        iat.saturating_add(self.days * DAY_SECS)
    }
}

impl Default for Grace {
    fn default() -> Self {
        Self {
            days: DEFAULT_GRACE_DAYS,
        }
    }
}

/// SHA-256 of the 32-byte public key: the form of a rotation commitment `next_key_sha256`.
pub fn key_sha256(key: &VerifyingKey) -> Sha256 {
    sha256(key.as_bytes())
}

fn proof_payload(
    iss: &Address,
    new_key: &KeyId,
    next_key_sha256: Sha256,
    previous_valid_until: UnixSecs,
) -> KeyProof {
    KeyProof {
        v: V1,
        iss: iss.clone(),
        new_key: new_key.clone(),
        next_key_sha256,
        previous_valid_until,
    }
}

fn replacement_payload(
    iss: &Address,
    revoked_key: &KeyId,
    new_key: &KeyId,
    next_key_sha256: Sha256,
) -> KeyReplacementProof {
    KeyReplacementProof {
        v: V1,
        iss: iss.clone(),
        revoked_key: revoked_key.clone(),
        new_key: new_key.clone(),
        next_key_sha256,
    }
}

/// The `data` of a `key.revoke` event from `iss` declaring `revoked` compromised, with the
/// replacement `new` signed by itself, if any. The caller seals the envelope with `revoked`.
///
/// # Panics
/// Never: a replacement proof always serialises.
pub fn key_revoke_data(
    iss: &Address,
    revoked: &VerifyingKey,
    replacement: Option<(&SigningKey, Sha256)>,
) -> KeyRevokeData {
    let revoked_key = key_id(revoked);
    let replacement = replacement.map(|(new, next_key_sha256)| {
        let new_key = key_id(&new.verifying_key());
        let proof = replacement_payload(iss, &revoked_key, &new_key, next_key_sha256);
        let payload = serde_json::to_vec(&proof).expect("replacement proof serialises");
        KeyReplacement {
            new_key,
            next_key_sha256,
            proof: token::sign(new, Typ::KeyReplacement, &payload),
        }
    });
    KeyRevokeData {
        revoked_key,
        replacement,
    }
}

/// The `data` of a `key.rotate` event from `iss` to `new`, with the proof of possession signed by
/// `new`. The caller seals the envelope with the key being replaced.
///
/// # Panics
/// Never: a key proof always serialises.
pub fn key_rotate_data(
    iss: &Address,
    new: &SigningKey,
    next_key_sha256: Sha256,
    previous_valid_until: UnixSecs,
) -> KeyRotateData {
    let new_key = key_id(&new.verifying_key());
    let proof = proof_payload(iss, &new_key, next_key_sha256, previous_valid_until);
    let payload = serde_json::to_vec(&proof).expect("key proof serialises");
    KeyRotateData {
        new_key,
        next_key_sha256,
        previous_valid_until,
        proof: token::sign(new, Typ::KeyProof, &payload),
    }
}

/// What a key event that passed every signature check did to the peer record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyChange {
    /// The new key matched the commitment on record and is now the current key.
    Installed,
    /// The current key no longer counts and no key was installed.
    Revoked,
    /// The new key is held as the pending change; only the receiving owner can make it current.
    OwnerConfirmationRequired,
}

/// Why a `key.rotate` or `key.revoke` envelope was refused. The record is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyChangeRefused {
    /// The envelope does not verify with the current key; `bad_signature`.
    NotCurrentKey(TokenError),
    /// Not a payload of the event type, a new key that is not an Ed25519 key, a `revoked_key`
    /// that is not the current key, or a replacement equal to it; `malformed`.
    Payload,
    /// The proof is not signed by the new key or covers another change; `bad_signature`.
    Proof,
}

/// No pending key change names the confirmed key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoPendingChange;

/// A key change held until the receiving owner confirms it (ADR 0013, "Change without a usable
/// commitment").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingKeyChange {
    new_key: VerifyingKey,
    next_key_sha256: Sha256,
    previous_valid_until: Option<UnixSecs>,
}

impl PendingKeyChange {
    /// The key that becomes current on confirmation.
    pub fn new_key(&self) -> &VerifyingKey {
        &self.new_key
    }
}

/// The keys a gate records for one peer address (ADR 0013 "Peer record").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKeys {
    current: VerifyingKey,
    next_key_sha256: Option<Sha256>,
    previous: Option<(VerifyingKey, UnixSecs)>,
    revoked: bool,
    pending: Option<PendingKeyChange>,
}

impl PeerKeys {
    /// The record pairing creates: the key pinned from the exchange and its first commitment.
    pub fn paired(current: VerifyingKey, next_key_sha256: Option<Sha256>) -> Self {
        Self {
            current,
            next_key_sha256,
            previous: None,
            revoked: false,
            pending: None,
        }
    }

    /// The current key; once revoked it signs only key events and validates nothing else.
    pub fn current(&self) -> &VerifyingKey {
        &self.current
    }

    /// The commitment to the next key, if any.
    pub fn next_key_sha256(&self) -> Option<Sha256> {
        self.next_key_sha256
    }

    /// The previous key and its `previous_valid_until`, if any.
    pub fn previous(&self) -> Option<(VerifyingKey, UnixSecs)> {
        self.previous
    }

    /// Whether the peer declared its current key compromised (`key_revoked`).
    pub fn revoked(&self) -> bool {
        self.revoked
    }

    /// The key change waiting for the receiving owner's confirmation, if any.
    pub fn pending(&self) -> Option<&PendingKeyChange> {
        self.pending.as_ref()
    }

    /// The key `kid` names if it is valid at `now`: the unrevoked current key, or the previous
    /// key while `now < previous_valid_until`.
    pub fn valid(&self, kid: &KeyId, now: UnixSecs) -> Option<VerifyingKey> {
        if !self.revoked && *kid == key_id(&self.current) {
            return Some(self.current);
        }
        self.previous
            .filter(|(key, until)| now < *until && *kid == key_id(key))
            .map(|(key, _)| key)
    }

    /// Verifies a compact JWS of type `typ` signed by a key valid at `now`.
    ///
    /// # Errors
    /// [`TokenError`] on any failed check; a key not valid at `now` is
    /// [`TokenError::WrongKid`].
    pub fn verify(&self, jws: &str, typ: Typ, now: UnixSecs) -> Result<Vec<u8>, TokenError> {
        token::verify_with(jws, typ, |kid| self.valid(kid, now))
    }

    /// Verifies a mandate SD-JWT signed by a key valid at `now`.
    ///
    /// # Errors
    /// As [`Self::verify`].
    pub fn verify_mandate(&self, sd_jwt: &str, now: UnixSecs) -> Result<Vec<u8>, TokenError> {
        token::verify_mandate_with(sd_jwt, |kid| self.valid(kid, now))
    }

    /// Verifies a key event envelope: it must be signed by the current key, revoked or not.
    ///
    /// # Errors
    /// [`KeyChangeRefused::NotCurrentKey`].
    pub fn verify_key_event(&self, jws: &str) -> Result<Vec<u8>, KeyChangeRefused> {
        token::verify(jws, Typ::Envelope, &self.current).map_err(KeyChangeRefused::NotCurrentKey)
    }

    /// Applies a `key.rotate` envelope (PROTOCOL §10.6). When SHA-256 of `new_key` equals the
    /// commitment on record, `new_key` becomes current and the replaced key stays valid until
    /// `min(previous_valid_until, iat + 30 days)`, or not at all once revoked. Otherwise
    /// `new_key` becomes the pending change and the current key stays as it was.
    ///
    /// # Errors
    /// [`KeyChangeRefused`] for the first failed check.
    pub fn rotate(&mut self, jws: &str) -> Result<KeyChange, KeyChangeRefused> {
        let payload = self.verify_key_event(jws)?;
        let env: Envelope<KeyRotateData> =
            serde_json::from_slice(&payload).map_err(|_| KeyChangeRefused::Payload)?;
        let d = &env.data;
        let new_key = key_from_id(&d.new_key).map_err(|_| KeyChangeRefused::Payload)?;
        let proof = token::verify(&d.proof, Typ::KeyProof, &new_key)
            .ok()
            .and_then(|p| serde_json::from_slice::<KeyProof>(&p).ok())
            .ok_or(KeyChangeRefused::Proof)?;
        let covered = proof_payload(
            &env.iss,
            &d.new_key,
            d.next_key_sha256,
            d.previous_valid_until,
        );
        if proof != covered {
            return Err(KeyChangeRefused::Proof);
        }
        let until = (!self.revoked).then(|| {
            d.previous_valid_until
                .min(env.iat.saturating_add(MAX_GRACE_SECS))
        });
        Ok(self.change(PendingKeyChange {
            new_key,
            next_key_sha256: d.next_key_sha256,
            previous_valid_until: until,
        }))
    }

    /// Applies a `key.revoke` envelope (PROTOCOL §10.7). The current key stops counting at once
    /// and the previous key's grace ends. A replacement whose SHA-256 equals the commitment on
    /// record becomes current; any other replacement becomes the pending change.
    ///
    /// # Errors
    /// [`KeyChangeRefused`] for the first failed check.
    pub fn revoke(&mut self, jws: &str) -> Result<KeyChange, KeyChangeRefused> {
        let payload = self.verify_key_event(jws)?;
        let env: Envelope<KeyRevokeData> =
            serde_json::from_slice(&payload).map_err(|_| KeyChangeRefused::Payload)?;
        let d = &env.data;
        if d.revoked_key != key_id(&self.current) {
            return Err(KeyChangeRefused::Payload);
        }
        let replacement = d
            .replacement
            .as_ref()
            .map(|r| verified_replacement(&env.iss, &d.revoked_key, r))
            .transpose()?;
        self.revoked = true;
        self.previous = None;
        self.pending = None;
        Ok(match replacement {
            None => KeyChange::Revoked,
            Some(change) => self.change(change),
        })
    }

    /// Makes the pending change current once the receiving owner confirmed `new_key` after
    /// comparing the key-change SAS ([`crate::hash::key_change_sas`]).
    ///
    /// # Errors
    /// [`NoPendingChange`] when no pending change names `new_key`; the record is unchanged.
    pub fn confirm_change(&mut self, new_key: &KeyId) -> Result<(), NoPendingChange> {
        let change = self
            .pending
            .filter(|p| key_id(&p.new_key) == *new_key)
            .ok_or(NoPendingChange)?;
        self.install(change);
        Ok(())
    }

    fn change(&mut self, change: PendingKeyChange) -> KeyChange {
        if self.next_key_sha256 == Some(key_sha256(&change.new_key)) {
            self.install(change);
            KeyChange::Installed
        } else {
            self.pending = Some(change);
            KeyChange::OwnerConfirmationRequired
        }
    }

    fn install(&mut self, change: PendingKeyChange) {
        self.previous = change
            .previous_valid_until
            .map(|until| (self.current, until));
        self.current = change.new_key;
        self.next_key_sha256 = Some(change.next_key_sha256);
        self.revoked = false;
        self.pending = None;
    }
}

/// The replacement of a `key.revoke` from `iss` once its key parses, differs from the revoked
/// key and signed a proof covering exactly this revocation.
fn verified_replacement(
    iss: &Address,
    revoked_key: &KeyId,
    r: &KeyReplacement,
) -> Result<PendingKeyChange, KeyChangeRefused> {
    if r.new_key == *revoked_key {
        return Err(KeyChangeRefused::Payload);
    }
    let new_key = key_from_id(&r.new_key).map_err(|_| KeyChangeRefused::Payload)?;
    let proof = token::verify(&r.proof, Typ::KeyReplacement, &new_key)
        .ok()
        .and_then(|p| serde_json::from_slice::<KeyReplacementProof>(&p).ok())
        .ok_or(KeyChangeRefused::Proof)?;
    if proof != replacement_payload(iss, revoked_key, &r.new_key, r.next_key_sha256) {
        return Err(KeyChangeRefused::Proof);
    }
    Ok(PendingKeyChange {
        new_key,
        next_key_sha256: r.next_key_sha256,
        previous_valid_until: None,
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use paseka_proto::envelope::EventType;
    use paseka_proto::envelope::KeyReplacement;

    use super::*;
    use crate::envelope::seal;
    use crate::testkit::{address, event, key};

    const IAT: UnixSecs = 1_794_268_830;
    const DAY: u64 = DAY_SECS;

    /// alice rotates from key 1 to key 2 and commits to key 3.
    fn rotation(edit: impl FnOnce(&mut KeyRotateData)) -> Envelope<KeyRotateData> {
        let mut data = key_rotate_data(
            &address(1),
            &key(2),
            key_sha256(&key(3).verifying_key()),
            IAT + 7 * DAY,
        );
        edit(&mut data);
        Envelope {
            v: V1,
            iss: address(1),
            aud: address(2),
            id: event(1),
            kind: EventType::KeyRotate,
            iat: IAT,
            data,
        }
    }

    /// alice revokes key 1, replacing it with `replacement` (key, commitment seed) if any.
    fn revocation(replacement: Option<(u8, u8)>) -> Envelope<KeyRevokeData> {
        revocation_edited(replacement, |_| {})
    }

    fn revocation_edited(
        replacement: Option<(u8, u8)>,
        edit: impl FnOnce(&mut KeyRevokeData),
    ) -> Envelope<KeyRevokeData> {
        let new = replacement.map(|(new, next)| (key(new), key_sha256(&key(next).verifying_key())));
        let mut data = key_revoke_data(
            &address(1),
            &key(1).verifying_key(),
            new.as_ref().map(|(k, next)| (k, *next)),
        );
        edit(&mut data);
        Envelope {
            v: V1,
            iss: address(1),
            aud: address(2),
            id: event(2),
            kind: EventType::KeyRevoke,
            iat: IAT,
            data,
        }
    }

    fn replacement(d: &mut KeyRevokeData) -> &mut KeyReplacement {
        d.replacement.as_mut().expect("a replacement")
    }

    fn committed() -> PeerKeys {
        PeerKeys::paired(
            key(1).verifying_key(),
            Some(key_sha256(&key(2).verifying_key())),
        )
    }

    fn rotated() -> PeerKeys {
        let mut keys = committed();
        keys.rotate(&seal(&key(1), &rotation(|_| {}))).unwrap();
        keys
    }

    #[test]
    fn rotation_is_accepted_only_with_current_key_valid_proof_and_matching_commitment() {
        let other_proof = |signer: u8, iss: u8| {
            move |d: &mut KeyRotateData| {
                d.proof = key_rotate_data(
                    &address(iss),
                    &key(signer),
                    d.next_key_sha256,
                    d.previous_valid_until,
                )
                .proof;
            }
        };
        let after_rotation = rotated();
        let cases: Vec<(&str, PeerKeys, String, Result<KeyChange, KeyChangeRefused>)> = vec![
            (
                "genuine",
                committed(),
                seal(&key(1), &rotation(|_| {})),
                Ok(KeyChange::Installed),
            ),
            (
                "signed by a stranger",
                committed(),
                seal(&key(9), &rotation(|_| {})),
                Err(KeyChangeRefused::NotCurrentKey(TokenError::WrongKid)),
            ),
            (
                "signed by the previous key in its grace",
                after_rotation.clone(),
                seal(&key(1), &rotation(|_| {})),
                Err(KeyChangeRefused::NotCurrentKey(TokenError::WrongKid)),
            ),
            (
                "proof signed by another key",
                committed(),
                seal(&key(1), &rotation(other_proof(9, 1))),
                Err(KeyChangeRefused::Proof),
            ),
            (
                "proof by new_key for another address",
                committed(),
                seal(&key(1), &rotation(other_proof(2, 3))),
                Err(KeyChangeRefused::Proof),
            ),
            (
                "proof by new_key for another grace",
                committed(),
                seal(
                    &key(1),
                    &rotation(|d| d.previous_valid_until = IAT + 30 * DAY),
                ),
                Err(KeyChangeRefused::Proof),
            ),
            (
                "no commitment on record",
                PeerKeys::paired(key(1).verifying_key(), None),
                seal(&key(1), &rotation(|_| {})),
                Ok(KeyChange::OwnerConfirmationRequired),
            ),
            (
                "commitment to another key",
                PeerKeys::paired(
                    key(1).verifying_key(),
                    Some(key_sha256(&key(4).verifying_key())),
                ),
                seal(&key(1), &rotation(|_| {})),
                Ok(KeyChange::OwnerConfirmationRequired),
            ),
        ];
        for (name, mut keys, jws, want) in cases {
            let before = keys.clone();
            assert_eq!(keys.rotate(&jws), want, "{name}");
            if want.is_err() {
                assert_eq!(keys, before, "{name}: record changed");
            }
            if want == Ok(KeyChange::OwnerConfirmationRequired) {
                assert_eq!(
                    (keys.current(), keys.previous(), keys.next_key_sha256()),
                    (
                        before.current(),
                        before.previous(),
                        before.next_key_sha256()
                    ),
                    "{name}: keys changed"
                );
            }
        }
    }

    #[test]
    fn a_new_key_that_is_not_an_ed25519_point_is_a_payload_error() {
        let point_less = (0..=u8::MAX)
            .map(|b| [b; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .expect("some byte pattern is not a curve point");
        let kid = KeyId::new(format!("ed25519:{}", URL_SAFE_NO_PAD.encode(point_less))).unwrap();
        let jws = seal(&key(1), &rotation(|d| d.new_key = kid));
        assert_eq!(committed().rotate(&jws), Err(KeyChangeRefused::Payload));
    }

    #[test]
    fn an_accepted_rotation_moves_the_keys_and_caps_the_grace_at_thirty_days() {
        let keys = rotated();
        assert_eq!(*keys.current(), key(2).verifying_key());
        assert_eq!(
            keys.next_key_sha256(),
            Some(key_sha256(&key(3).verifying_key()))
        );
        assert_eq!(
            keys.previous(),
            Some((key(1).verifying_key(), IAT + 7 * DAY))
        );

        let mut capped = committed();
        let long = rotation(|d| {
            *d = key_rotate_data(&address(1), &key(2), d.next_key_sha256, IAT + 90 * DAY);
        });
        capped.rotate(&seal(&key(1), &long)).unwrap();
        assert_eq!(
            capped.previous(),
            Some((key(1).verifying_key(), IAT + 30 * DAY))
        );
    }

    #[test]
    fn the_previous_key_is_valid_only_before_previous_valid_until() {
        let keys = rotated();
        let (old, new) = (
            key_id(&key(1).verifying_key()),
            key_id(&key(2).verifying_key()),
        );
        let until = IAT + 7 * DAY;
        let table = [
            (&new, until + 1, Some(key(2).verifying_key())),
            (&old, until - 1, Some(key(1).verifying_key())),
            (&old, until, None),
            (&key_id(&key(9).verifying_key()), IAT, None),
        ];
        for (kid, now, want) in table {
            assert_eq!(keys.valid(kid, now), want, "{kid} at {now}");
        }
    }

    #[test]
    fn grace_is_a_whole_number_of_days_from_one_to_thirty() {
        for (days, ok) in [(0, false), (1, true), (30, true), (31, false)] {
            assert_eq!(Grace::days(days).is_ok(), ok, "{days} days");
        }
        assert_eq!(Grace::days(1).unwrap().previous_valid_until(IAT), IAT + DAY);
    }

    type Case = (
        &'static str,
        PeerKeys,
        String,
        Result<KeyChange, KeyChangeRefused>,
    );

    /// Replaces the replacement proof by one signed by `signer` for `iss` revoking `revoked`.
    fn other_proof(signer: u8, iss: u8, revoked: u8) -> impl FnOnce(&mut KeyRevokeData) {
        move |d| {
            let next = replacement(d).next_key_sha256;
            let data = key_revoke_data(
                &address(iss),
                &key(revoked).verifying_key(),
                Some((&key(signer), next)),
            );
            replacement(d).proof = data.replacement.expect("a replacement").proof;
        }
    }

    fn revocation_cases() -> Vec<Case> {
        let after_rotation = rotated();
        vec![
            (
                "alone",
                committed(),
                seal(&key(1), &revocation(None)),
                Ok(KeyChange::Revoked),
            ),
            (
                "committed replacement",
                committed(),
                seal(&key(1), &revocation(Some((2, 3)))),
                Ok(KeyChange::Installed),
            ),
            (
                "uncommitted replacement",
                committed(),
                seal(&key(1), &revocation(Some((9, 3)))),
                Ok(KeyChange::OwnerConfirmationRequired),
            ),
            (
                "signed by a stranger",
                committed(),
                seal(&key(9), &revocation(None)),
                Err(KeyChangeRefused::NotCurrentKey(TokenError::WrongKid)),
            ),
            (
                "signed by the previous key in its grace",
                after_rotation,
                seal(&key(1), &revocation(None)),
                Err(KeyChangeRefused::NotCurrentKey(TokenError::WrongKid)),
            ),
            (
                "revoked_key is not the current key",
                committed(),
                seal(
                    &key(1),
                    &revocation_edited(None, |d| d.revoked_key = key_id(&key(9).verifying_key())),
                ),
                Err(KeyChangeRefused::Payload),
            ),
            (
                "replacement is the revoked key",
                committed(),
                seal(
                    &key(1),
                    &revocation_edited(Some((2, 3)), |d| {
                        replacement(d).new_key = key_id(&key(1).verifying_key());
                    }),
                ),
                Err(KeyChangeRefused::Payload),
            ),
            (
                "replacement proof signed by another key",
                committed(),
                seal(
                    &key(1),
                    &revocation_edited(Some((2, 3)), other_proof(9, 1, 1)),
                ),
                Err(KeyChangeRefused::Proof),
            ),
            (
                "replacement proof for another address",
                committed(),
                seal(
                    &key(1),
                    &revocation_edited(Some((2, 3)), other_proof(2, 3, 1)),
                ),
                Err(KeyChangeRefused::Proof),
            ),
            (
                "replacement proof for another revoked key",
                committed(),
                seal(
                    &key(1),
                    &revocation_edited(Some((2, 3)), other_proof(2, 1, 9)),
                ),
                Err(KeyChangeRefused::Proof),
            ),
            (
                "replacement proof for another commitment",
                committed(),
                seal(
                    &key(1),
                    &revocation_edited(Some((2, 3)), |d| {
                        replacement(d).next_key_sha256 = key_sha256(&key(4).verifying_key());
                    }),
                ),
                Err(KeyChangeRefused::Proof),
            ),
        ]
    }

    #[test]
    fn revocation_by_the_current_key_removes_authority_and_installs_only_a_committed_key() {
        let (old, new) = (
            key_id(&key(1).verifying_key()),
            key_id(&key(2).verifying_key()),
        );
        for (name, mut keys, jws, want) in revocation_cases() {
            let before = keys.clone();
            assert_eq!(keys.revoke(&jws), want, "{name}");
            match want {
                Err(_) => assert_eq!(keys, before, "{name}: record changed"),
                Ok(KeyChange::Installed) => {
                    assert_eq!(*keys.current(), key(2).verifying_key(), "{name}");
                    assert_eq!(keys.previous(), None, "{name}: grace for the revoked key");
                    assert!(!keys.revoked(), "{name}");
                    assert_eq!(keys.valid(&old, IAT), None, "{name}: revoked key valid");
                    assert!(keys.valid(&new, IAT).is_some(), "{name}");
                }
                Ok(_) => {
                    assert_eq!(keys.current(), before.current(), "{name}: key installed");
                    assert!(keys.revoked(), "{name}: not marked revoked");
                    assert_eq!(keys.valid(&old, IAT), None, "{name}: revoked key valid");
                }
            }
        }
    }

    #[test]
    fn revocation_ends_the_grace_of_the_previous_key() {
        let mut keys = rotated();
        let old = key_id(&key(1).verifying_key());
        assert!(keys.valid(&old, IAT).is_some());
        let revoke = Envelope {
            data: key_revoke_data(&address(1), &key(2).verifying_key(), None),
            ..revocation(None)
        };
        assert_eq!(keys.revoke(&seal(&key(2), &revoke)), Ok(KeyChange::Revoked));
        assert_eq!(keys.previous(), None);
        assert_eq!(keys.valid(&old, IAT), None);
        assert_eq!(keys.valid(&key_id(&key(2).verifying_key()), IAT), None);
    }

    #[test]
    fn a_revoked_peer_still_rotates_to_its_committed_key_without_grace_for_the_revoked_one() {
        let mut keys = committed();
        keys.revoke(&seal(&key(1), &revocation(None))).unwrap();
        assert_eq!(
            keys.rotate(&seal(&key(1), &rotation(|_| {}))),
            Ok(KeyChange::Installed)
        );
        assert_eq!(*keys.current(), key(2).verifying_key());
        assert_eq!(keys.previous(), None);
        assert!(!keys.revoked());
    }

    #[test]
    fn an_unconfirmed_change_keeps_the_old_key_until_the_owner_confirms_the_new_one() {
        let (old, new, other) = (
            key_id(&key(1).verifying_key()),
            key_id(&key(2).verifying_key()),
            key_id(&key(9).verifying_key()),
        );
        let mut keys = PeerKeys::paired(key(1).verifying_key(), None);
        assert_eq!(
            keys.rotate(&seal(&key(1), &rotation(|_| {}))),
            Ok(KeyChange::OwnerConfirmationRequired)
        );
        assert_eq!(
            keys.pending().map(PendingKeyChange::new_key),
            Some(&key(2).verifying_key())
        );
        assert!(keys.valid(&old, IAT).is_some());
        assert_eq!(keys.valid(&new, IAT), None);
        let before = keys.clone();
        assert_eq!(keys.confirm_change(&other), Err(NoPendingChange));
        assert_eq!(keys, before);

        keys.confirm_change(&new).unwrap();
        assert_eq!(*keys.current(), key(2).verifying_key());
        assert_eq!(
            keys.previous(),
            Some((key(1).verifying_key(), IAT + 7 * DAY))
        );
        assert_eq!(
            keys.next_key_sha256(),
            Some(key_sha256(&key(3).verifying_key()))
        );
        assert_eq!(keys.pending(), None);
        assert_eq!(keys.confirm_change(&new), Err(NoPendingChange));
    }

    #[test]
    fn a_confirmed_revocation_replacement_gives_the_revoked_key_no_grace() {
        let (revoked, replacement) = (
            key_id(&key(1).verifying_key()),
            key_id(&key(9).verifying_key()),
        );
        let mut keys = committed();
        assert_eq!(
            keys.revoke(&seal(&key(1), &revocation(Some((9, 3))))),
            Ok(KeyChange::OwnerConfirmationRequired)
        );
        assert_eq!(keys.valid(&revoked, IAT), None);
        assert_eq!(keys.valid(&replacement, IAT), None);
        keys.confirm_change(&replacement).unwrap();
        assert_eq!(*keys.current(), key(9).verifying_key());
        assert_eq!(keys.previous(), None);
        assert!(!keys.revoked());
        assert_eq!(keys.valid(&revoked, IAT), None);
        assert!(keys.valid(&replacement, IAT).is_some());
    }

    #[test]
    fn a_later_key_event_replaces_the_pending_change() {
        let mut keys = PeerKeys::paired(key(1).verifying_key(), None);
        keys.rotate(&seal(&key(1), &rotation(|_| {}))).unwrap();
        keys.revoke(&seal(&key(1), &revocation(None))).unwrap();
        assert_eq!(keys.pending(), None);
        keys.revoke(&seal(&key(1), &revocation(Some((9, 3)))))
            .unwrap();
        assert_eq!(
            keys.confirm_change(&key_id(&key(2).verifying_key())),
            Err(NoPendingChange)
        );
        assert_eq!(
            keys.pending().map(PendingKeyChange::new_key),
            Some(&key(9).verifying_key())
        );
    }
}
