//! Draft lifecycle (PROTOCOL §4.1) and approval-request checks (§7.1).
//!
//! Every revision gets its own approval request; a new revision, withdrawal, denial or expiry
//! revokes it. A decision is accepted only for the live request of the current revision, with
//! the stored release digest, through a channel strong enough for the required level. A draft
//! lives until its `expires`; no prompt and no mandate outlive it.

use std::ops::RangeInclusive;

use paseka_proto::draft::{DraftKind, DraftState, Reason};
use paseka_proto::evidence::{Channel, Decision};
use paseka_proto::mandate::AttachmentMeta;
use paseka_proto::tools::{Delivery, DraftView};
use paseka_proto::{
    DraftId, Level, MessageId, Nonce, PeerHandle, RequestId, Sha256, TenantId, ThreadId, UnixSecs,
};

use crate::hash::approval_challenge;
use crate::risk::Required;

/// A live or used approval request of one revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// Request id.
    pub request_id: RequestId,
    /// Revision it belongs to.
    pub revision: u32,
    /// Gate nonce, secret from the agent.
    pub nonce: Nonce,
    /// Required level.
    pub level: Level,
    /// Approval challenge (PROTOCOL §3.3).
    pub challenge: Sha256,
    /// Issue time.
    pub issued_at: UnixSecs,
    /// End of the prompt TTL.
    pub expires_at: UnixSecs,
}

/// Fresh identifiers for a new approval request, drawn by the caller from the OS CSPRNG.
#[derive(Debug, Clone)]
pub struct RequestSeed {
    /// Request id.
    pub request_id: RequestId,
    /// Nonce.
    pub nonce: Nonce,
}

/// One revision's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision {
    /// Body.
    pub body: String,
    /// Attachment metadata in order.
    pub attachments: Vec<AttachmentMeta>,
    /// Release digest of this revision.
    pub release_digest: Sha256,
    /// Whether the owner authored it.
    pub by_owner: bool,
}

/// An outbound draft as stored by the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    /// Owning tenant.
    pub tenant: TenantId,
    /// Id.
    pub id: DraftId,
    /// What was proposed.
    pub kind: DraftKind,
    /// Recipient.
    pub to: PeerHandle,
    /// Thread.
    pub thread: ThreadId,
    /// Inbox item answered.
    pub in_reply_to: Option<MessageId>,
    /// Current revision number, from 1.
    pub revision: u32,
    /// Current revision.
    pub current: Revision,
    /// State.
    pub state: DraftState,
    /// Reason of a terminal state other than `released`.
    pub reason: Option<Reason>,
    /// Approval request of the current revision while awaiting consent.
    pub request: Option<ApprovalRequest>,
    /// Creation time.
    pub created_at: UnixSecs,
    /// End of the draft lifetime, bound into every release digest ([`draft_expires`]).
    pub expires: UnixSecs,
    /// Last change.
    pub updated_at: UnixSecs,
}

/// A refused draft operation, mapped to the agent error codes of PROTOCOL §5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftError {
    /// `invalid_state`.
    InvalidState(DraftState),
    /// `revision_conflict`.
    RevisionConflict,
}

/// A refused owner decision (PROTOCOL §7.1). The draft is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionError {
    /// No live request with this id in this tenant (other tenants' ids included).
    UnknownRequest,
    /// The nonce does not belong to the request.
    NonceMismatch,
    /// The prompt TTL passed.
    Expired,
    /// The draft is not awaiting consent.
    NotAwaiting,
    /// The stored digest differs from the one recomputed or sent by the channel.
    DigestMismatch,
    /// The channel cannot satisfy the required level.
    ChannelTooWeak,
    /// The decider is not an approver of the tenant.
    NotApprover,
}

/// An owner decision as received from an approval channel.
#[derive(Debug, Clone, Copy)]
pub struct DecisionAttempt<'a> {
    /// Tenant resolved from the channel, never from a payload.
    pub tenant: &'a TenantId,
    /// Request id from the channel.
    pub request_id: &'a RequestId,
    /// Nonce from the channel.
    pub nonce: &'a Nonce,
    /// The channel.
    pub channel: Channel,
    /// Whether the decider is a configured approver of `tenant`.
    pub approver: bool,
    /// Release digest recomputed from the stored revision (and, for A2, sent by the page).
    pub release_digest: Sha256,
    /// Approve or deny.
    pub decision: Decision,
}

/// What an accepted approval hands to mandate issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    /// The consumed nonce.
    pub nonce: Nonce,
    /// Level satisfied.
    pub level: Level,
    /// Challenge the evidence records.
    pub challenge: Sha256,
    /// Release digest approved.
    pub release_digest: Sha256,
}

/// Prompt TTL bounds and default (PROTOCOL §7.1).
pub const PROMPT_TTL_DEFAULT: u64 = 3600;

/// Default draft lifetime (PROTOCOL §4): 12 h.
pub const DRAFT_LIFETIME_DEFAULT: u64 = 12 * 3600;
/// Allowed owner settings of the draft lifetime (PROTOCOL §4): 5 min to 7 days.
pub const DRAFT_LIFETIME_RANGE: RangeInclusive<u64> = 300..=7 * 86_400;

/// A draft lifetime setting outside [`DRAFT_LIFETIME_RANGE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifetimeOutOfRange(pub u64);

/// `expires` of a draft created at `created_at` under the owner's lifetime setting `lifetime`.
///
/// # Errors
/// [`LifetimeOutOfRange`] unless `lifetime` is in [`DRAFT_LIFETIME_RANGE`].
pub fn draft_expires(created_at: UnixSecs, lifetime: u64) -> Result<UnixSecs, LifetimeOutOfRange> {
    if DRAFT_LIFETIME_RANGE.contains(&lifetime) {
        Ok(created_at.saturating_add(lifetime))
    } else {
        Err(LifetimeOutOfRange(lifetime))
    }
}

impl Draft {
    fn open_request(&mut self, level: Level, seed: RequestSeed, now: UnixSecs, ttl: u64) {
        let challenge = approval_challenge(
            &self.tenant,
            &seed.request_id,
            self.current.release_digest,
            &seed.nonce,
            level,
        );
        self.request = Some(ApprovalRequest {
            request_id: seed.request_id,
            revision: self.revision,
            nonce: seed.nonce,
            level,
            challenge,
            issued_at: now,
            expires_at: now.saturating_add(ttl).min(self.expires),
        });
        self.state = DraftState::AwaitingConsent;
    }

    fn terminate(&mut self, state: DraftState, reason: Reason, now: UnixSecs) {
        self.state = state;
        self.reason = Some(reason);
        self.request = None;
        self.updated_at = now;
    }

    /// Applies the evaluation of the current revision. `strongest` is the strongest configured
    /// channel; a requirement above it blocks (PROTOCOL §6.2). An A0 result moves to `approved`;
    /// the caller then commits the release in the same transaction.
    pub fn evaluated(
        &mut self,
        required: Required,
        strongest: Channel,
        seed: RequestSeed,
        now: UnixSecs,
        ttl: u64,
    ) {
        self.updated_at = now;
        match required {
            Required::Block => self.terminate(DraftState::Blocked, Reason::Policy, now),
            Required::Level(Level::A0) => {
                self.request = None;
                self.state = DraftState::Approved;
            }
            Required::Level(l) if !strongest.satisfies(l) => {
                self.terminate(DraftState::Blocked, Reason::Policy, now);
            }
            Required::Level(l) => self.open_request(l, seed, now, ttl),
        }
    }

    /// Agent `revise`: replaces the content and revokes the old request. The caller evaluates
    /// the new revision and calls [`Self::evaluated`].
    ///
    /// # Errors
    /// [`DraftError`] unless the draft awaits consent at revision `revision`.
    pub fn revise(
        &mut self,
        revision: u32,
        next: Revision,
        now: UnixSecs,
    ) -> Result<(), DraftError> {
        if self.state != DraftState::AwaitingConsent {
            return Err(DraftError::InvalidState(self.state));
        }
        if revision != self.revision {
            return Err(DraftError::RevisionConflict);
        }
        self.revision += 1;
        self.current = next;
        self.request = None;
        self.updated_at = now;
        Ok(())
    }

    /// Agent `withdraw`.
    ///
    /// # Errors
    /// [`DraftError::InvalidState`] unless the draft awaits consent.
    pub fn withdraw(&mut self, now: UnixSecs) -> Result<(), DraftError> {
        if self.state != DraftState::AwaitingConsent {
            return Err(DraftError::InvalidState(self.state));
        }
        self.terminate(DraftState::Withdrawn, Reason::Agent, now);
        Ok(())
    }

    /// Whether the gate may issue a closed mandate for this draft at `now`: approved, or released
    /// and re-issuing for a retry, and before `expires`.
    pub fn may_issue_mandate(&self, now: UnixSecs) -> bool {
        matches!(self.state, DraftState::Approved | DraftState::Released) && now < self.expires
    }

    /// Prompt TTL, mandate expiry or the end of the draft lifetime.
    pub fn expire(&mut self, now: UnixSecs) {
        let due = match self.state {
            DraftState::AwaitingConsent => {
                now >= self.expires || self.request.as_ref().is_none_or(|r| now >= r.expires_at)
            }
            DraftState::Approved => true,
            _ => false,
        };
        if due {
            self.terminate(DraftState::Expired, Reason::Timeout, now);
        }
    }

    /// An owner decision through an approval channel. On approval the request is consumed and
    /// the draft moves to `approved`; on denial to `denied`.
    ///
    /// # Errors
    /// [`DecisionError`] when any check of PROTOCOL §7.1 fails; the draft is unchanged.
    pub fn decide(
        &mut self,
        a: &DecisionAttempt<'_>,
        now: UnixSecs,
    ) -> Result<Option<Approved>, DecisionError> {
        if a.tenant != &self.tenant {
            return Err(DecisionError::UnknownRequest);
        }
        let Some(req) = self
            .request
            .as_ref()
            .filter(|r| &r.request_id == a.request_id)
        else {
            return Err(DecisionError::UnknownRequest);
        };
        if &req.nonce != a.nonce {
            return Err(DecisionError::NonceMismatch);
        }
        if now >= req.expires_at {
            return Err(DecisionError::Expired);
        }
        if self.state != DraftState::AwaitingConsent || req.revision != self.revision {
            return Err(DecisionError::NotAwaiting);
        }
        if a.release_digest != self.current.release_digest {
            return Err(DecisionError::DigestMismatch);
        }
        if !a.channel.satisfies(req.level) {
            return Err(DecisionError::ChannelTooWeak);
        }
        if !a.approver {
            return Err(DecisionError::NotApprover);
        }
        let approved = Approved {
            nonce: req.nonce.clone(),
            level: req.level,
            challenge: req.challenge,
            release_digest: self.current.release_digest,
        };
        match a.decision {
            Decision::Approve => {
                self.request = None;
                self.state = DraftState::Approved;
                self.updated_at = now;
                Ok(Some(approved))
            }
            Decision::Deny => {
                self.terminate(DraftState::Denied, Reason::Owner, now);
                Ok(None)
            }
        }
    }

    /// The agent's view: state, coarse reason and content only (SP-8). `delivery` is required
    /// once released.
    pub fn view(&self, delivery: Option<Delivery>) -> DraftView {
        DraftView {
            draft_id: self.id.clone(),
            revision: self.revision,
            kind: self.kind,
            to: self.to.clone(),
            thread: self.thread.clone(),
            in_reply_to: self.in_reply_to.clone(),
            state: self.state,
            reason: self.reason,
            body: self.current.body.clone(),
            attachments: self.current.attachments.clone(),
            content_sha256: crate::hash::content_sha256(&self.current.body),
            edited_by_owner: self.current.by_owner,
            created_at: self.created_at,
            updated_at: self.updated_at,
            expires_at: self.request.as_ref().map(|r| r.expires_at),
            delivery,
        }
    }

    /// Outbox commit of an approved draft; at or after `expires` the draft expires instead.
    ///
    /// # Errors
    /// [`DraftError::InvalidState`] unless the draft is `approved` and alive.
    pub fn release(&mut self, now: UnixSecs) -> Result<(), DraftError> {
        if self.state == DraftState::Approved && now >= self.expires {
            self.expire(now);
        }
        if self.state != DraftState::Approved {
            return Err(DraftError::InvalidState(self.state));
        }
        self.state = DraftState::Released;
        self.updated_at = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{draft_id, nonce, peer, request_id, tenant, thread};

    fn seed(i: u8) -> RequestSeed {
        RequestSeed {
            request_id: request_id(i),
            nonce: nonce(i),
        }
    }

    fn rev(body: &str) -> Revision {
        Revision {
            body: body.into(),
            attachments: vec![],
            release_digest: crate::hash::content_sha256(body),
            by_owner: false,
        }
    }

    fn awaiting(level: Level) -> Draft {
        let mut d = Draft {
            tenant: tenant(1),
            id: draft_id(1),
            kind: DraftKind::FreeText,
            to: peer("bob"),
            thread: thread(1),
            in_reply_to: None,
            revision: 1,
            current: rev("hi"),
            state: DraftState::AwaitingConsent,
            reason: None,
            request: None,
            created_at: 0,
            expires: 1000,
            updated_at: 0,
        };
        d.evaluated(
            Required::Level(level),
            Channel::TelegramMiniApp,
            seed(1),
            10,
            100,
        );
        d
    }

    fn attempt(d: &Draft, channel: Channel) -> DecisionAttempt<'_> {
        let r = d.request.as_ref().unwrap();
        DecisionAttempt {
            tenant: &d.tenant,
            request_id: &r.request_id,
            nonce: &r.nonce,
            channel,
            approver: true,
            release_digest: d.current.release_digest,
            decision: Decision::Approve,
        }
    }

    #[test]
    fn approval_consumes_the_request_once() {
        let snap = awaiting(Level::A1);
        let mut d = snap.clone();
        let a = attempt(&snap, Channel::TelegramButton);
        assert!(d.decide(&a, 20).unwrap().is_some());
        assert_eq!(d.state, DraftState::Approved);
        assert_eq!(d.decide(&a, 21), Err(DecisionError::UnknownRequest));
    }

    #[test]
    fn revise_revokes_the_old_request_and_checks_the_revision() {
        let mut d = awaiting(Level::A1);
        let old = d.request.clone().unwrap();
        assert_eq!(
            d.revise(2, rev("hi!"), 11),
            Err(DraftError::RevisionConflict)
        );
        d.revise(1, rev("hi!"), 11).unwrap();
        d.evaluated(
            Required::Level(Level::A1),
            Channel::TelegramMiniApp,
            seed(2),
            11,
            100,
        );
        let snap = d.clone();
        let a = DecisionAttempt {
            request_id: &old.request_id,
            nonce: &old.nonce,
            ..attempt(&snap, Channel::TelegramButton)
        };
        assert_eq!(d.decide(&a, 12), Err(DecisionError::UnknownRequest));
    }

    #[test]
    fn decisions_fail_closed_on_every_check() {
        let d = awaiting(Level::A2);
        let other = tenant(2);
        let cases: [(DecisionAttempt<'_>, DecisionError); 5] = [
            (
                DecisionAttempt {
                    tenant: &other,
                    ..attempt(&d, Channel::TelegramMiniApp)
                },
                DecisionError::UnknownRequest,
            ),
            (
                DecisionAttempt {
                    nonce: &nonce(9),
                    ..attempt(&d, Channel::TelegramMiniApp)
                },
                DecisionError::NonceMismatch,
            ),
            (
                attempt(&d, Channel::TelegramButton),
                DecisionError::ChannelTooWeak,
            ),
            (
                DecisionAttempt {
                    approver: false,
                    ..attempt(&d, Channel::TelegramMiniApp)
                },
                DecisionError::NotApprover,
            ),
            (
                DecisionAttempt {
                    release_digest: Sha256([0; 32]),
                    ..attempt(&d, Channel::TelegramMiniApp)
                },
                DecisionError::DigestMismatch,
            ),
        ];
        for (a, want) in cases {
            assert_eq!(d.clone().decide(&a, 20), Err(want));
        }
        assert_eq!(
            d.clone()
                .decide(&attempt(&d, Channel::TelegramMiniApp), 110),
            Err(DecisionError::Expired)
        );
    }

    #[test]
    fn approved_drafts_cannot_be_revised_or_withdrawn() {
        let snap = awaiting(Level::A1);
        let mut d = snap.clone();
        d.decide(&attempt(&snap, Channel::TelegramButton), 20)
            .unwrap();
        assert_eq!(
            d.revise(1, rev("x"), 21),
            Err(DraftError::InvalidState(DraftState::Approved))
        );
        assert_eq!(
            d.withdraw(21),
            Err(DraftError::InvalidState(DraftState::Approved))
        );
    }

    #[test]
    fn a_level_above_every_channel_blocks() {
        let d = awaiting(Level::A2Plus);
        assert_eq!(
            (d.state, d.reason),
            (DraftState::Blocked, Some(Reason::Policy))
        );
    }

    #[test]
    fn the_lifetime_setting_is_bounded() {
        let (lo, hi) = (*DRAFT_LIFETIME_RANGE.start(), *DRAFT_LIFETIME_RANGE.end());
        assert_eq!(draft_expires(1000, lo), Ok(1300));
        assert_eq!(draft_expires(1000, hi), Ok(1000 + 604_800));
        assert!(draft_expires(1000, DRAFT_LIFETIME_DEFAULT).is_ok());
        for bad in [0, lo - 1, hi + 1] {
            assert_eq!(draft_expires(1000, bad), Err(LifetimeOutOfRange(bad)));
        }
    }

    #[test]
    fn no_prompt_outlives_the_draft() {
        let mut d = awaiting(Level::A1);
        d.expires = 50;
        d.revise(1, rev("hi!"), 20).unwrap();
        d.evaluated(
            Required::Level(Level::A1),
            Channel::TelegramMiniApp,
            seed(2),
            20,
            100,
        );
        let snap = d.clone();
        assert_eq!(
            d.decide(&attempt(&snap, Channel::TelegramButton), 50),
            Err(DecisionError::Expired)
        );
        d.expire(50);
        assert_eq!(
            (d.state, d.reason),
            (DraftState::Expired, Some(Reason::Timeout))
        );
    }

    #[test]
    fn no_mandate_is_issued_at_or_after_expires() {
        let snap = awaiting(Level::A1);
        let mut d = snap.clone();
        d.decide(&attempt(&snap, Channel::TelegramButton), 20)
            .unwrap();
        assert!(d.may_issue_mandate(999));
        assert!(!d.may_issue_mandate(1000));
        let mut late = d.clone();
        assert_eq!(
            late.release(1000),
            Err(DraftError::InvalidState(DraftState::Expired))
        );
        assert!(!late.may_issue_mandate(1000));
        d.release(999).unwrap();
        assert!(d.may_issue_mandate(999));
        assert!(!d.may_issue_mandate(1000));
    }
}
