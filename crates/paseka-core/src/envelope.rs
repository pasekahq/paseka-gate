//! Gate-to-gate envelope verification: signature by a paired gate, addressing, freshness and
//! replay.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;
use paseka_proto::envelope::{ENVELOPE_V, Envelope};
use paseka_proto::jws::TYP_ENVELOPE;
use paseka_proto::{GateId, Nonce, UnixSecs};

use crate::token::{self, TokenError};

/// Accepted clock difference between gates, either way.
pub const FRESHNESS_SECS: u64 = 300;

/// Why an envelope is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Token-level failure; an unpaired sender reads as [`TokenError::UnknownKey`].
    Token(TokenError),
    /// Payload is not a valid envelope.
    Payload,
    /// Unsupported version.
    Version,
    /// `from` differs from the signing key.
    SenderMismatch,
    /// Addressed to another gate.
    NotForUs,
    /// `sent_at` outside the freshness window.
    Stale,
    /// `msg_id` already seen from this sender.
    Replay,
}

/// Paired gates' keys and the replay window.
#[derive(Debug, Clone, Default)]
pub struct Inbound {
    peers: BTreeMap<String, VerifyingKey>,
    seen: BTreeSet<(UnixSecs, GateId, Nonce)>,
    seen_ids: BTreeSet<(GateId, Nonce)>,
}

impl Inbound {
    /// Pairs a gate by its key.
    pub fn pair(&mut self, key: VerifyingKey) {
        self.peers.insert(token::kid_of(&key), key);
    }

    /// Verifies an envelope addressed to `me` and records its id.
    ///
    /// # Errors
    /// [`EnvelopeError`] naming the first failed check.
    pub fn accept(
        &mut self,
        token: &str,
        me: &GateId,
        now: UnixSecs,
    ) -> Result<Envelope, EnvelopeError> {
        let peers = &self.peers;
        let (kid, payload) = token::verify(token, TYP_ENVELOPE, |kid| {
            peers.get_key_value(kid).map(|(k, v)| (v, k.clone()))
        })
        .map_err(EnvelopeError::Token)?;
        let env: Envelope = serde_json::from_slice(&payload).map_err(|_| EnvelopeError::Payload)?;
        if env.v != ENVELOPE_V {
            return Err(EnvelopeError::Version);
        }
        if env.from.as_str() != kid {
            return Err(EnvelopeError::SenderMismatch);
        }
        if &env.to != me {
            return Err(EnvelopeError::NotForUs);
        }
        if env.sent_at.abs_diff(now) > FRESHNESS_SECS {
            return Err(EnvelopeError::Stale);
        }
        self.prune(now);
        if !self.seen_ids.insert((env.from.clone(), env.msg_id.clone())) {
            return Err(EnvelopeError::Replay);
        }
        self.seen
            .insert((env.sent_at, env.from.clone(), env.msg_id.clone()));
        Ok(env)
    }

    /// Forgets ids too old to pass the freshness check anyway.
    fn prune(&mut self, now: UnixSecs) {
        let cutoff = now.saturating_sub(FRESHNESS_SECS);
        while let Some(first) = self.seen.first().cloned() {
            if first.0 >= cutoff {
                break;
            }
            self.seen.remove(&first);
            self.seen_ids.remove(&(first.1, first.2));
        }
    }
}

#[cfg(test)]
mod tests {
    use paseka_proto::envelope::Body;

    use super::*;
    use crate::testkit::{key, nonce};

    fn gate(seed: u8) -> GateId {
        GateId::new(token::kid_of(&key(seed).verifying_key())).unwrap()
    }

    fn envelope(from: u8, to: u8, id: u8, sent_at: UnixSecs) -> String {
        let env = Envelope {
            v: ENVELOPE_V,
            from: gate(from),
            to: gate(to),
            msg_id: nonce(id),
            sent_at,
            body: Body::Question {
                thread: "t1".into(),
                text: "what does bob think about x".into(),
            },
        };
        let k = key(from);
        token::sign(
            &k,
            &token::kid_of(&k.verifying_key()),
            TYP_ENVELOPE,
            &serde_json::to_vec(&env).unwrap(),
        )
    }

    fn inbound() -> Inbound {
        let mut i = Inbound::default();
        i.pair(key(1).verifying_key());
        i
    }

    #[test]
    fn paired_fresh_envelope_is_accepted_once() {
        let mut i = inbound();
        let t = envelope(1, 2, 1, 1000);
        assert!(i.accept(&t, &gate(2), 1000).is_ok());
        assert_eq!(i.accept(&t, &gate(2), 1001), Err(EnvelopeError::Replay));
    }

    #[test]
    fn unpaired_misaddressed_and_stale_envelopes_are_refused() {
        let mut i = inbound();
        assert_eq!(
            i.accept(&envelope(3, 2, 1, 1000), &gate(2), 1000),
            Err(EnvelopeError::Token(TokenError::UnknownKey))
        );
        assert_eq!(
            i.accept(&envelope(1, 3, 1, 1000), &gate(2), 1000),
            Err(EnvelopeError::NotForUs)
        );
        assert_eq!(
            i.accept(
                &envelope(1, 2, 1, 1000),
                &gate(2),
                1000 + FRESHNESS_SECS + 1
            ),
            Err(EnvelopeError::Stale)
        );
    }

    #[test]
    fn sender_field_must_match_the_signing_key() {
        let mut i = inbound();
        i.pair(key(3).verifying_key());
        let env = Envelope {
            v: ENVELOPE_V,
            from: gate(3),
            to: gate(2),
            msg_id: nonce(1),
            sent_at: 1000,
            body: Body::Unknown,
        };
        let k = key(1);
        let t = token::sign(
            &k,
            &token::kid_of(&k.verifying_key()),
            TYP_ENVELOPE,
            &serde_json::to_vec(&env).unwrap(),
        );
        assert_eq!(
            i.accept(&t, &gate(2), 1000),
            Err(EnvelopeError::SenderMismatch)
        );
    }
}
