//! Closed mandates: issuance by the sending gate and verification by the receiving gate
//! (PROTOCOL §8.2, §8.4).

use ed25519_dalek::SigningKey;
use paseka_proto::envelope::{Envelope, MessageData};
use paseka_proto::evidence::Channel;
use paseka_proto::mandate::ClosedMandate;
use paseka_proto::{Address, Level, MandateId, TenantId, UnixSecs};

use crate::envelope::SKEW_SECS;
use crate::hash::{Release, content_sha256, release_digest, sha256};
use crate::peer::PeerKeys;
use crate::tenant::TenantMap;
use crate::token::{self, TokenError};

/// Closed mandate lifetime, `exp - iat` (PROTOCOL §8.2, §14).
pub const CLOSED_TTL_SECS: u64 = 60;
/// Most attachments per message.
pub const MAX_ATTACHMENTS: usize = 8;

/// Why a received mandate was refused. Every variant maps to `mandate_invalid` except
/// [`Self::Replay`] (`mandate_replay`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MandateInvalid {
    /// JWS checks of §8.1 failed.
    Token(TokenError),
    /// Payload is not a closed mandate.
    Payload,
    /// `iss` or `to` differ from the envelope, or `tenant` is not the `iss` address.
    Addressing,
    /// Body or attachments differ from what the mandate covers.
    Content,
    /// `thread` or `in_reply_to` differ.
    Thread,
    /// The release digest does not recompute.
    Digest,
    /// Outside its validity window.
    Time,
    /// Issued at or after the draft `expires`.
    DraftExpired,
    /// `level` and `proof.channel` are inconsistent.
    Proof,
    /// `jti` seen before from this sender.
    Replay,
}

/// Checks that `level` and `proof` agree (PROTOCOL §6.3, `contracts/mandate/closed`): A0 iff an
/// open mandate is named and the channel is `open-mandate`; otherwise a channel that satisfies
/// the level.
///
/// # Errors
/// [`MandateInvalid::Proof`] on any inconsistency.
pub fn check_proof(m: &ClosedMandate) -> Result<(), MandateInvalid> {
    let p = &m.proof;
    let a0 = m.level == Level::A0;
    let ok = a0 == (p.channel == Channel::OpenMandate)
        && a0 == p.open_mandate.is_some()
        && p.channel.satisfies(m.level)
        && m.attachments.len() <= MAX_ATTACHMENTS;
    if ok {
        Ok(())
    } else {
        Err(MandateInvalid::Proof)
    }
}

/// Signs a closed mandate with the sending tenant's key.
///
/// # Panics
/// Never: the claims always serialise.
pub fn issue(key: &SigningKey, m: &ClosedMandate) -> String {
    let payload = serde_json::to_vec(m).expect("mandate claims serialise");
    token::sign_mandate(key, &payload)
}

/// Mandate ids accepted per receiving tenant and sender address, kept until they expire.
#[derive(Debug, Clone, Default)]
pub struct JtiBook {
    seen: TenantMap<(Address, MandateId), UnixSecs>,
}

impl JtiBook {
    /// Whether `jti` from `iss` was accepted before by `tenant`.
    pub fn seen(&self, tenant: &TenantId, iss: &Address, jti: &MandateId) -> bool {
        self.seen.get(tenant, &(iss.clone(), jti.clone())).is_some()
    }

    /// Records an accepted mandate.
    pub fn record(&mut self, tenant: &TenantId, m: &ClosedMandate) {
        self.seen
            .insert(tenant, (m.iss.clone(), m.jti.clone()), m.exp);
    }

    /// Drops ids whose mandate expired more than [`SKEW_SECS`] ago; they can no longer verify.
    pub fn prune(&mut self, now: UnixSecs) {
        self.seen
            .retain(|_, exp| exp.saturating_add(SKEW_SECS) > now);
    }
}

/// Verifies the mandate of a received `message` event (PROTOCOL §8.4); `sender` is the key
/// record of the envelope `iss`, and the mandate must be signed by a key valid at `now`. The
/// caller records the returned mandate in the [`JtiBook`]
/// in the same transaction as the inbox item.
///
/// # Errors
/// [`MandateInvalid`] for the first failed check.
pub fn verify_received(
    env: &Envelope<MessageData>,
    sender: &PeerKeys,
    receiver_tenant: &TenantId,
    jtis: &JtiBook,
    now: UnixSecs,
) -> Result<ClosedMandate, MandateInvalid> {
    let d = &env.data;
    let payload = sender
        .verify_mandate(&d.mandate, now)
        .map_err(MandateInvalid::Token)?;
    let m: ClosedMandate = serde_json::from_slice(&payload).map_err(|_| MandateInvalid::Payload)?;
    if m.iss != env.iss || m.to != env.aud || m.tenant.address() != m.iss {
        return Err(MandateInvalid::Addressing);
    }
    let bytes_match = d.attachments.iter().all(|a| {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&a.data)
            .is_ok_and(|b| b.len() as u64 == a.meta.size && sha256(&b) == a.meta.sha256)
    });
    let metas_match = m.attachments.len() == d.attachments.len()
        && m.attachments
            .iter()
            .zip(&d.attachments)
            .all(|(x, y)| *x == y.meta);
    if m.content_sha256 != content_sha256(&d.body) || !metas_match || !bytes_match {
        return Err(MandateInvalid::Content);
    }
    if m.thread != d.thread || m.in_reply_to != d.in_reply_to {
        return Err(MandateInvalid::Thread);
    }
    let digest = release_digest(&Release {
        tenant: &m.tenant,
        iss: &env.iss,
        to: &env.aud,
        thread: &d.thread,
        in_reply_to: d.in_reply_to.as_ref(),
        expires: m.expires,
        content_sha256: m.content_sha256,
        attachments: &m.attachments,
    });
    if digest != m.release_digest {
        return Err(MandateInvalid::Digest);
    }
    let window = m.iat <= env.iat && env.iat <= m.exp && m.exp - m.iat <= CLOSED_TTL_SECS;
    if !window || m.iat > now.saturating_add(SKEW_SECS) {
        return Err(MandateInvalid::Time);
    }
    if m.iat >= m.expires {
        return Err(MandateInvalid::DraftExpired);
    }
    check_proof(&m)?;
    if jtis.seen(receiver_tenant, &m.iss, &m.jti) {
        return Err(MandateInvalid::Replay);
    }
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{seed_key, vectors};

    struct Signed {
        claims: ClosedMandate,
        env: Envelope<MessageData>,
        alice: SigningKey,
    }

    fn signed() -> Signed {
        let v = vectors();
        let signed = &v["signed"];
        Signed {
            claims: serde_json::from_value(signed["closed_mandate"]["claims"].clone()).unwrap(),
            env: serde_json::from_value(signed["envelope"]["payload"].clone()).unwrap(),
            alice: seed_key(&v, "alice"),
        }
    }

    fn bob() -> TenantId {
        TenantId::new("t_01JD0000000000000000000002").unwrap()
    }

    fn redigest(m: &mut ClosedMandate) {
        m.release_digest = release_digest(&Release {
            tenant: &m.tenant,
            iss: &m.iss,
            to: &m.to,
            thread: &m.thread,
            in_reply_to: m.in_reply_to.as_ref(),
            expires: m.expires,
            content_sha256: m.content_sha256,
            attachments: &m.attachments,
        });
    }

    /// Verifies `s` with its mandate replaced by alice's signature over `m`, at `m.iat + 1`.
    fn verify_claims(s: &Signed, m: &ClosedMandate) -> Result<ClosedMandate, MandateInvalid> {
        let mut env = s.env.clone();
        env.data.mandate = issue(&s.alice, m);
        let keys = PeerKeys::paired(s.alice.verifying_key(), None);
        verify_received(&env, &keys, &bob(), &JtiBook::default(), m.iat + 1)
    }

    #[test]
    fn issuance_reproduces_the_vector_and_the_receiver_accepts_it() {
        let v = vectors();
        let s = signed();
        let compact = issue(&s.alice, &s.claims);
        assert_eq!(
            compact,
            v["signed"]["closed_mandate"]["compact"].as_str().unwrap()
        );
        let now = s.claims.iat + 1;
        let mut jtis = JtiBook::default();
        let alice_keys = PeerKeys::paired(s.alice.verifying_key(), None);
        let m = verify_received(&s.env, &alice_keys, &bob(), &jtis, now).unwrap();
        jtis.record(&bob(), &m);
        assert_eq!(
            verify_received(&s.env, &alice_keys, &bob(), &jtis, now),
            Err(MandateInvalid::Replay)
        );
    }

    #[test]
    fn the_receiver_binds_the_draft_expiry() {
        let s = signed();
        let c = &s.claims;
        let stretched = ClosedMandate {
            expires: c.expires + 3600,
            ..c.clone()
        };
        let mut late = ClosedMandate {
            expires: c.iat,
            ..c.clone()
        };
        redigest(&mut late);
        let mut last_second = ClosedMandate {
            expires: c.iat + 1,
            ..c.clone()
        };
        redigest(&mut last_second);
        let cases = [
            (c.clone(), Ok(())),
            (last_second, Ok(())),
            (stretched, Err(MandateInvalid::Digest)),
            (late, Err(MandateInvalid::DraftExpired)),
        ];
        for (m, want) in cases {
            assert_eq!(
                verify_claims(&s, &m).map(|_| ()),
                want,
                "expires {}",
                m.expires
            );
        }
    }

    #[test]
    fn the_closed_mandate_lifetime_and_the_skew_are_inclusive() {
        let s = signed();
        let c = &s.claims;
        let lasting = |secs| ClosedMandate {
            exp: c.iat + secs,
            ..c.clone()
        };
        assert_eq!(
            verify_claims(&s, &lasting(CLOSED_TTL_SECS)).map(|_| ()),
            Ok(())
        );
        assert_eq!(
            verify_claims(&s, &lasting(CLOSED_TTL_SECS + 1)).map(|_| ()),
            Err(MandateInvalid::Time)
        );
        let keys = PeerKeys::paired(s.alice.verifying_key(), None);
        let at = |now| verify_received(&s.env, &keys, &bob(), &JtiBook::default(), now);
        assert!(at(c.iat - SKEW_SECS).is_ok());
        assert_eq!(at(c.iat - SKEW_SECS - 1), Err(MandateInvalid::Time));
    }

    #[test]
    fn a_mandate_whose_tenant_is_not_its_issuer_address_is_refused() {
        let s = signed();
        let mut m = s.claims.clone();
        m.tenant = TenantId::new("t_01JD0000000000000000000003").unwrap();
        redigest(&mut m);
        assert_eq!(verify_claims(&s, &m), Err(MandateInvalid::Addressing));
    }
}
