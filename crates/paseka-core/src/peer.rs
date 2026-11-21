//! Peer key records and routine key rotation (PROTOCOL §2, §10.6; ADR 0013).

use std::ops::RangeInclusive;

use ed25519_dalek::{SigningKey, VerifyingKey};
use paseka_proto::envelope::{Envelope, KeyProof, KeyRotateData};
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

/// What a rotation that passed every signature check did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    /// `new_key` matched the commitment on record and is now the current key.
    Rotated,
    /// No commitment on record or `new_key` does not match it. The record is unchanged; only the
    /// receiving owner can accept the key.
    OwnerConfirmationRequired,
}

/// Why a `key.rotate` envelope was refused. The record is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationRefused {
    /// The envelope does not verify with the current key; `bad_signature`.
    NotCurrentKey(TokenError),
    /// Not a `key.rotate` payload, or `new_key` is not an Ed25519 key; `malformed`.
    Payload,
    /// The proof is not signed by `new_key` or covers another rotation; `bad_signature`.
    Proof,
}

/// The keys a gate records for one peer address (ADR 0013 "Peer record").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKeys {
    current: VerifyingKey,
    next_key_sha256: Option<Sha256>,
    previous: Option<(VerifyingKey, UnixSecs)>,
}

impl PeerKeys {
    /// The record pairing creates: the key pinned from the exchange and its first commitment.
    pub fn paired(current: VerifyingKey, next_key_sha256: Option<Sha256>) -> Self {
        Self {
            current,
            next_key_sha256,
            previous: None,
        }
    }

    /// The current key.
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

    /// The key `kid` names if it is valid at `now`: the current key, or the previous key while
    /// `now < previous_valid_until`.
    pub fn valid(&self, kid: &KeyId, now: UnixSecs) -> Option<VerifyingKey> {
        if *kid == key_id(&self.current) {
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

    /// Applies a `key.rotate` envelope (PROTOCOL §10.6). It auto-accepts only when the envelope
    /// verifies with the current key, the proof with `new_key`, and SHA-256 of `new_key` equals
    /// the commitment on record; then the current key becomes previous until
    /// `min(previous_valid_until, iat + 30 days)`, `new_key` becomes current and the new
    /// commitment is stored.
    ///
    /// # Errors
    /// [`RotationRefused`] for the first failed check.
    pub fn rotate(&mut self, jws: &str) -> Result<Rotation, RotationRefused> {
        let payload = token::verify(jws, Typ::Envelope, &self.current)
            .map_err(RotationRefused::NotCurrentKey)?;
        let env: Envelope<KeyRotateData> =
            serde_json::from_slice(&payload).map_err(|_| RotationRefused::Payload)?;
        let d = &env.data;
        let new_key = key_from_id(&d.new_key).map_err(|_| RotationRefused::Payload)?;
        let proof = token::verify(&d.proof, Typ::KeyProof, &new_key)
            .ok()
            .and_then(|p| serde_json::from_slice::<KeyProof>(&p).ok())
            .ok_or(RotationRefused::Proof)?;
        let covered = proof_payload(
            &env.iss,
            &d.new_key,
            d.next_key_sha256,
            d.previous_valid_until,
        );
        if proof != covered {
            return Err(RotationRefused::Proof);
        }
        if self.next_key_sha256 != Some(key_sha256(&new_key)) {
            return Ok(Rotation::OwnerConfirmationRequired);
        }
        let until = d
            .previous_valid_until
            .min(env.iat.saturating_add(MAX_GRACE_SECS));
        self.previous = Some((self.current, until));
        self.current = new_key;
        self.next_key_sha256 = Some(d.next_key_sha256);
        Ok(Rotation::Rotated)
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use paseka_proto::envelope::EventType;

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
        let cases: Vec<(&str, PeerKeys, String, Result<Rotation, RotationRefused>)> = vec![
            (
                "genuine",
                committed(),
                seal(&key(1), &rotation(|_| {})),
                Ok(Rotation::Rotated),
            ),
            (
                "signed by a stranger",
                committed(),
                seal(&key(9), &rotation(|_| {})),
                Err(RotationRefused::NotCurrentKey(TokenError::WrongKid)),
            ),
            (
                "signed by the previous key in its grace",
                after_rotation.clone(),
                seal(&key(1), &rotation(|_| {})),
                Err(RotationRefused::NotCurrentKey(TokenError::WrongKid)),
            ),
            (
                "proof signed by another key",
                committed(),
                seal(&key(1), &rotation(other_proof(9, 1))),
                Err(RotationRefused::Proof),
            ),
            (
                "proof by new_key for another address",
                committed(),
                seal(&key(1), &rotation(other_proof(2, 3))),
                Err(RotationRefused::Proof),
            ),
            (
                "proof by new_key for another grace",
                committed(),
                seal(
                    &key(1),
                    &rotation(|d| d.previous_valid_until = IAT + 30 * DAY),
                ),
                Err(RotationRefused::Proof),
            ),
            (
                "no commitment on record",
                PeerKeys::paired(key(1).verifying_key(), None),
                seal(&key(1), &rotation(|_| {})),
                Ok(Rotation::OwnerConfirmationRequired),
            ),
            (
                "commitment to another key",
                PeerKeys::paired(
                    key(1).verifying_key(),
                    Some(key_sha256(&key(4).verifying_key())),
                ),
                seal(&key(1), &rotation(|_| {})),
                Ok(Rotation::OwnerConfirmationRequired),
            ),
        ];
        for (name, mut keys, jws, want) in cases {
            let before = keys.clone();
            assert_eq!(keys.rotate(&jws), want, "{name}");
            if want != Ok(Rotation::Rotated) {
                assert_eq!(keys, before, "{name}: record changed");
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
        assert_eq!(committed().rotate(&jws), Err(RotationRefused::Payload));
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
}
