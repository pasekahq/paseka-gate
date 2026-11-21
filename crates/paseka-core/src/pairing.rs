//! Pairing (PROTOCOL §11): invite lifetime, the invitee's check of a pair accept against the
//! pair URI, and the verification a peer needs for trust above T1.

use ed25519_dalek::VerifyingKey;
use paseka_proto::evidence::Channel;
use paseka_proto::jws::Typ;
use paseka_proto::pairing::PairAccept;
use paseka_proto::{Address, KeyId, OpenTrust, TenantId, UnixSecs};

use crate::channel::SETTING_LEVEL;
use crate::hash::sha256;
use crate::tenant::TenantMap;
use crate::token::{self, TokenError};

/// Default invite lifetime (PROTOCOL §11 step 1, §14).
pub const INVITE_TTL_DEFAULT: u64 = 86_400;
/// Longest invite lifetime the inviter may choose (PROTOCOL §11 step 1, §14).
pub const INVITE_TTL_MAX: u64 = 7 * 86_400;

/// An invite lifetime above [`INVITE_TTL_MAX`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteTtlTooLong(pub u64);

/// `expires_at` of an invite created at `created_at` with lifetime `ttl`.
///
/// # Errors
/// [`InviteTtlTooLong`] when `ttl` exceeds [`INVITE_TTL_MAX`].
pub fn invite_expires(created_at: UnixSecs, ttl: u64) -> Result<UnixSecs, InviteTtlTooLong> {
    if ttl <= INVITE_TTL_MAX {
        Ok(created_at.saturating_add(ttl))
    } else {
        Err(InviteTtlTooLong(ttl))
    }
}

/// What the invitee expects of the accept: the inviter named by the pair URI and its own request.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// Inviter address, `a` of the pair URI.
    pub inviter: &'a Address,
    /// Inviter key, `k` of the pair URI.
    pub inviter_key: &'a KeyId,
    /// Invitee address, `iss` of the request.
    pub invitee: &'a Address,
    /// The pair request sent, as compact JWS.
    pub request: &'a str,
}

/// Why a pair accept was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptInvalid {
    /// JWS checks failed: `typ`, a `kid` other than the URI key, or the signature.
    Token(TokenError),
    /// Payload is not a pair accept.
    Payload,
    /// `iss` or `key` differ from the pair URI.
    Inviter,
    /// `aud` is not the invitee.
    Audience,
    /// `request_sha256` does not hash the request sent.
    Request,
}

/// Verifies a pair accept (PROTOCOL §11 step 5). On success the invitee pins the returned key
/// for `inviter`.
///
/// # Errors
/// [`AcceptInvalid`] for the first failed check.
pub fn verify_accept(
    accept: &str,
    want: &Expected<'_>,
) -> Result<(PairAccept, VerifyingKey), AcceptInvalid> {
    let key = token::key_from_id(want.inviter_key).map_err(AcceptInvalid::Token)?;
    let payload = token::verify(accept, Typ::Pair, &key).map_err(AcceptInvalid::Token)?;
    let a: PairAccept = serde_json::from_slice(&payload).map_err(|_| AcceptInvalid::Payload)?;
    if &a.iss != want.inviter || &a.key != want.inviter_key {
        return Err(AcceptInvalid::Inviter);
    }
    if &a.aud != want.invitee {
        return Err(AcceptInvalid::Audience);
    }
    if a.request_sha256 != sha256(want.request.as_bytes()) {
        return Err(AcceptInvalid::Request);
    }
    Ok((a, key))
}

/// Whether the owner compared the short authentication string of the pairing with the peer's
/// owner (PROTOCOL §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// The comparison was skipped.
    NotVerified,
    /// The owner confirmed that both strings match.
    Sas,
}

/// Whether open mandates above T1 need a verified peer: a security setting of the tenant
/// (PROTOCOL §9.4, §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Requirement {
    /// T2, T3 and conversation trust need a peer verified by the SAS.
    #[default]
    On,
    /// Any trust may be granted to a peer that is not verified.
    Off,
}

/// What the verification rule looks at for one peer of one tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationCheck {
    /// The peer's verification.
    pub peer: Verification,
    /// The tenant's [`Requirement`].
    pub requirement: Requirement,
}

impl VerificationCheck {
    /// Whether an open mandate of `trust` may be presented to the owner or signed for this peer.
    /// Every trust above T1 needs the check, conversation trust included: it releases free text,
    /// where T1 releases only rendered templates.
    pub fn allows(self, trust: OpenTrust) -> bool {
        trust == OpenTrust::T1
            || self.peer == Verification::Sas
            || self.requirement == Requirement::Off
    }
}

/// A [`Requirement`] change through a channel below the settings floor A2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingTooWeak;

/// Per-tenant [`Requirement`].
#[derive(Debug, Clone, Default)]
pub struct RequirementBook {
    tenants: TenantMap<(), Requirement>,
}

impl RequirementBook {
    /// The tenant's requirement; [`Requirement::On`] until the owner changes it.
    pub fn requirement(&self, tenant: &TenantId) -> Requirement {
        self.tenants.get(tenant, &()).copied().unwrap_or_default()
    }

    /// Changes the tenant's requirement through an owner settings decision by `channel`.
    ///
    /// # Errors
    /// [`SettingTooWeak`] for a channel below A2, the open mandate included.
    pub fn set(
        &mut self,
        tenant: &TenantId,
        requirement: Requirement,
        channel: Channel,
    ) -> Result<(), SettingTooWeak> {
        if !channel.satisfies(SETTING_LEVEL) {
            return Err(SettingTooWeak);
        }
        self.tenants.insert(tenant, (), requirement);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use serde_json::Value;

    use super::*;
    use crate::testkit::{seed_key, tenant, vectors};

    fn party(v: &Value, name: &str) -> (SigningKey, KeyId, Address) {
        let k = &v["signing_keys"][name];
        (
            seed_key(v, name),
            serde_json::from_value(k["key_id"].clone()).unwrap(),
            serde_json::from_value(k["address"].clone()).unwrap(),
        )
    }

    #[test]
    fn the_vector_accept_binds_the_uri_address_and_key() {
        let v = vectors();
        let (alice, alice_kid, alice_addr) = party(&v, "alice");
        let (_, _, bob_addr) = party(&v, "bob");
        let (carol, carol_kid, carol_addr) = party(&v, "carol");
        let signed = &v["signed"];
        let request = signed["pair_request"]["compact"].as_str().unwrap();
        let accept = signed["pair_accept"]["compact"].as_str().unwrap();
        let want = Expected {
            inviter: &alice_addr,
            inviter_key: &alice_kid,
            invitee: &bob_addr,
            request,
        };
        let (a, key) = verify_accept(accept, &want).unwrap();
        assert_eq!((a.iss, key), (alice_addr.clone(), alice.verifying_key()));

        let payload: PairAccept =
            serde_json::from_value(signed["pair_accept"]["payload"].clone()).unwrap();
        let sign = |k: &SigningKey, p: &PairAccept| {
            token::sign(k, Typ::Pair, &serde_json::to_vec(p).unwrap())
        };
        let mut by_carol = payload.clone();
        by_carol.key = carol_kid;
        assert_eq!(
            verify_accept(&sign(&carol, &by_carol), &want),
            Err(AcceptInvalid::Token(TokenError::WrongKid))
        );
        let mut wrong_iss = payload.clone();
        wrong_iss.iss = carol_addr;
        assert_eq!(
            verify_accept(&sign(&alice, &wrong_iss), &want),
            Err(AcceptInvalid::Inviter)
        );
        let mut wrong_aud = payload;
        wrong_aud.aud = alice_addr.clone();
        assert_eq!(
            verify_accept(&sign(&alice, &wrong_aud), &want),
            Err(AcceptInvalid::Audience)
        );
        let other_request = Expected {
            request: signed["receipt"]["compact"].as_str().unwrap(),
            ..want
        };
        assert_eq!(
            verify_accept(accept, &other_request),
            Err(AcceptInvalid::Request)
        );
    }

    #[test]
    fn the_verification_requirement_is_on_until_the_owner_turns_it_off_at_a2() {
        let mut book = RequirementBook::default();
        let (t, other) = (tenant(1), tenant(2));
        assert_eq!(book.requirement(&t), Requirement::On);
        for weak in [Channel::TelegramButton, Channel::OpenMandate] {
            assert_eq!(book.set(&t, Requirement::Off, weak), Err(SettingTooWeak));
        }
        assert_eq!(book.requirement(&t), Requirement::On);
        let a2 = Channel::TelegramMiniApp;
        assert_eq!(book.set(&t, Requirement::Off, a2), Ok(()));
        assert_eq!(
            (book.requirement(&t), book.requirement(&other)),
            (Requirement::Off, Requirement::On)
        );
        assert_eq!(book.set(&t, Requirement::On, a2), Ok(()));
        assert_eq!(book.requirement(&t), Requirement::On);
    }

    #[test]
    fn an_invite_lives_at_most_seven_days() {
        assert_eq!(invite_expires(1000, INVITE_TTL_DEFAULT), Ok(1000 + 86_400));
        assert_eq!(
            invite_expires(1000, INVITE_TTL_MAX),
            Ok(1000 + INVITE_TTL_MAX)
        );
        assert_eq!(
            invite_expires(1000, INVITE_TTL_MAX + 1),
            Err(InviteTtlTooLong(INVITE_TTL_MAX + 1))
        );
    }
}
