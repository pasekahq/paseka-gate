//! A small deterministic gate state: tenant alice, peer bob, one A2 approver key.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use paseka_core::hash::content_sha256;
use paseka_core::mandate::{self, MandateError, Outgoing};
use paseka_core::nonce::{Binding, NonceBook};
use paseka_core::token::{self, Approver, ApproverRing, kid_of};
use paseka_proto::evidence::{Channel, Proof};
use paseka_proto::jws::TYP_MANDATE;
use paseka_proto::mandate::{AttachmentRef, ClosedMandate, Mandate};
use paseka_proto::{Level, Nonce, PeerId, TenantId, UnixSecs};

pub(crate) const NOW: UnixSecs = 2_000_000_000;
pub(crate) const TEXT: &str = "Alice thinks X is promising but wants to see numbers first.";

pub(crate) fn tenant(s: &str) -> TenantId {
    TenantId::new(s).expect("fixture tenant")
}

pub(crate) fn peer(s: &str) -> PeerId {
    PeerId::new(s).expect("fixture peer")
}

pub(crate) fn nonce(i: u8) -> Nonce {
    Nonce::new(format!("conformance-nonce-{i:0>8}")).expect("fixture nonce")
}

pub(crate) fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(crate) struct Gate {
    pub(crate) ring: ApproverRing,
    pub(crate) nonces: NonceBook,
    pub(crate) approver: SigningKey,
}

impl Gate {
    /// Alice's gate with one A2 approver and nonce 1 issued for [`TEXT`] to bob.
    pub(crate) fn new() -> Self {
        let approver = key(41);
        let mut ring = ApproverRing::default();
        ring.insert(Approver {
            tenant: tenant("alice"),
            max_level: Level::A2,
            key: approver.verifying_key(),
        });
        let carol_approver = key(42);
        ring.insert(Approver {
            tenant: tenant("carol"),
            max_level: Level::A3,
            key: carol_approver.verifying_key(),
        });
        let mut nonces = NonceBook::default();
        nonces.issue(
            &tenant("alice"),
            nonce(1),
            Binding {
                to: peer("bob"),
                content_sha256: content_sha256(TEXT),
            },
            NOW + 60,
        );
        Self {
            ring,
            nonces,
            approver,
        }
    }

    pub(crate) fn release(
        &mut self,
        token: &str,
        to: &str,
        text: &str,
        attachments: &[AttachmentRef],
        required: Level,
        now: UnixSecs,
    ) -> Result<ClosedMandate, MandateError> {
        let (alice, to) = (tenant("alice"), peer(to));
        let out = Outgoing {
            tenant: &alice,
            to: &to,
            text,
            attachments,
        };
        mandate::verify_closed(&self.ring, &mut self.nonces, token, out, required, now)
    }
}

pub(crate) fn proof(channel: Channel) -> Proof {
    Proof {
        channel,
        evidence: serde_json::Map::new(),
    }
}

/// The closed mandate the owner would sign at A2 for [`TEXT`] to bob.
pub(crate) fn closed() -> ClosedMandate {
    ClosedMandate {
        tenant: tenant("alice"),
        to: peer("bob"),
        content_sha256: content_sha256(TEXT),
        attachments: vec![],
        level: Level::A2,
        proof: proof(Channel::TelegramMiniApp),
        nonce: nonce(1),
        exp: NOW + 60,
    }
}

pub(crate) fn sign(k: &SigningKey, m: &Mandate) -> String {
    let payload = serde_json::to_vec(m).expect("mandate serialises");
    token::sign(k, &kid_of(&k.verifying_key()), TYP_MANDATE, &payload)
}

pub(crate) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
