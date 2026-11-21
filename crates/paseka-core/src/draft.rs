//! Draft lifecycle (PROTOCOL §4.1) and approval-request checks (§7.1).
//!
//! Every revision gets its own approval request; a new revision, withdrawal, denial or expiry
//! revokes it. A decision is accepted only for the live request of the current revision, with
//! the stored release digest, through a channel that satisfies the request's floor
//! ([`Selection::floor`]). A draft lives until its `expires`; no prompt and no mandate outlive it.

use std::ops::RangeInclusive;

use paseka_proto::draft::{DraftKind, DraftState, Reason};
use paseka_proto::evidence::{Channel, Decision};
use paseka_proto::mandate::AttachmentMeta;
use paseka_proto::tools::{Delivery, DraftView, ThreadTrust};
use paseka_proto::{
    DraftId, Level, MessageId, Nonce, PeerHandle, RequestId, Sha256, TenantId, ThreadId, UnixSecs,
};

use crate::channel::{Channels, Selection};
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
    /// Configured channel the request goes through, marked when `level` is above every one.
    pub selection: Selection,
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
    /// `rate_limited`; the limit is for the owner, never for the agent.
    RateLimited(DraftLimit),
}

/// A draft limit of PROTOCOL §5.3 that refuses a new draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftLimit {
    /// [`PENDING_DRAFTS_PER_TENANT`] drafts already await consent.
    PendingPerTenant,
    /// [`DRAFTS_PER_PEER_PER_HOUR`] drafts to this peer within the last hour.
    PerPeerHour,
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
    /// The channel does not satisfy the request's floor.
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
    /// Level the closed mandate records: the request's floor, never above what the channel
    /// attests.
    pub level: Level,
    /// Level the request required. Above `level` only when no configured channel satisfied it;
    /// the evidence then records it as `required_level`.
    pub required: Level,
    /// Challenge the evidence records.
    pub challenge: Sha256,
    /// Release digest approved.
    pub release_digest: Sha256,
}

/// Default prompt TTL (PROTOCOL §7.1, §14).
pub const PROMPT_TTL_DEFAULT: u64 = 3600;
/// Allowed owner settings of the prompt TTL (PROTOCOL §7.1, §14).
pub const PROMPT_TTL_RANGE: RangeInclusive<u64> = 300..=86_400;

/// Default draft lifetime (PROTOCOL §4, §14).
pub const DRAFT_LIFETIME_DEFAULT: u64 = 12 * HOUR;
/// Allowed owner settings of the draft lifetime (PROTOCOL §4, §14).
pub const DRAFT_LIFETIME_RANGE: RangeInclusive<u64> = 300..=7 * 86_400;

/// Most drafts of one tenant in `awaiting_consent` (PROTOCOL §5.3, §14).
pub const PENDING_DRAFTS_PER_TENANT: usize = 50;
/// Most drafts the agent creates to one peer within any rolling hour (PROTOCOL §5.3, §14).
pub const DRAFTS_PER_PEER_PER_HOUR: usize = 30;

const HOUR: u64 = 3600;

/// A prompt TTL setting outside [`PROMPT_TTL_RANGE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromptTtlOutOfRange(pub u64);

/// The owner's prompt TTL setting `ttl`, checked against [`PROMPT_TTL_RANGE`].
///
/// # Errors
/// [`PromptTtlOutOfRange`] unless `ttl` is in [`PROMPT_TTL_RANGE`].
pub fn prompt_ttl(ttl: u64) -> Result<u64, PromptTtlOutOfRange> {
    if PROMPT_TTL_RANGE.contains(&ttl) {
        Ok(ttl)
    } else {
        Err(PromptTtlOutOfRange(ttl))
    }
}

/// Admits a new draft of `tenant` to `to` at `now` (PROTOCOL §5.3). `drafts` holds at least the
/// tenant's drafts awaiting consent and those created within the last hour; drafts of other
/// tenants are ignored. The caller runs it before evaluation, so a refusal reveals no level.
///
/// # Errors
/// [`DraftError::RateLimited`] naming the first limit reached.
pub fn admit(
    drafts: &[Draft],
    tenant: &TenantId,
    to: &PeerHandle,
    now: UnixSecs,
) -> Result<(), DraftError> {
    let own = || drafts.iter().filter(|d| &d.tenant == tenant);
    let pending = own()
        .filter(|d| d.state == DraftState::AwaitingConsent)
        .count();
    if pending >= PENDING_DRAFTS_PER_TENANT {
        return Err(DraftError::RateLimited(DraftLimit::PendingPerTenant));
    }
    let to_peer = own()
        .filter(|d| &d.to == to && d.created_at.saturating_add(HOUR) > now)
        .count();
    if to_peer >= DRAFTS_PER_PEER_PER_HOUR {
        return Err(DraftError::RateLimited(DraftLimit::PerPeerHour));
    }
    Ok(())
}

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
    fn open_request(
        &mut self,
        level: Level,
        selection: Selection,
        seed: RequestSeed,
        now: UnixSecs,
        ttl: u64,
    ) {
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
            selection,
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

    /// Applies the evaluation of the current revision. A level is never blocked for want of a
    /// channel: one above every configured channel goes through the strongest, marked
    /// (PROTOCOL §6.2). An A0 result moves to `approved`; the caller then commits the release in
    /// the same transaction.
    pub fn evaluated(
        &mut self,
        required: Required,
        channels: &Channels,
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
            Required::Level(l) => self.open_request(l, channels.select(l), seed, now, ttl),
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
        let floor = req.selection.floor(req.level);
        if !a.channel.satisfies(floor) {
            return Err(DecisionError::ChannelTooWeak);
        }
        if !a.approver {
            return Err(DecisionError::NotApprover);
        }
        let approved = Approved {
            nonce: req.nonce.clone(),
            level: floor,
            required: req.level,
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

    /// The agent's view: state, coarse reason, content and the thread's conversation trust from
    /// [`crate::open::thread_trust`] (SP-8). `delivery` is required once released.
    pub fn view(&self, delivery: Option<Delivery>, thread_trust: ThreadTrust) -> DraftView {
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
            thread_trust: Some(thread_trust),
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
    use crate::testkit::{awaiting, drafts, mvp_channels, nonce, peer, rev, seed, tenant};

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
        let snap = awaiting(1, 1, "hi", 0, 1000, Required::Level(Level::A1), 10);
        let mut d = snap.clone();
        let a = attempt(&snap, Channel::TelegramButton);
        assert!(d.decide(&a, 20).unwrap().is_some());
        assert_eq!(d.state, DraftState::Approved);
        assert_eq!(d.decide(&a, 21), Err(DecisionError::UnknownRequest));
    }

    #[test]
    fn revise_revokes_the_old_request_and_checks_the_revision() {
        let mut d = awaiting(1, 1, "hi", 0, 1000, Required::Level(Level::A1), 10);
        let old = d.request.clone().unwrap();
        assert_eq!(
            d.revise(2, rev("hi!"), 11),
            Err(DraftError::RevisionConflict)
        );
        d.revise(1, rev("hi!"), 11).unwrap();
        d.evaluated(
            Required::Level(Level::A1),
            &mvp_channels(),
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
        let d = awaiting(1, 1, "hi", 0, 1000, Required::Level(Level::A2), 10);
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
        let snap = awaiting(1, 1, "hi", 0, 1000, Required::Level(Level::A1), 10);
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
    fn a_level_above_every_channel_goes_through_the_strongest_marked() {
        let d = awaiting(1, 1, "hi", 0, 1000, Required::Level(Level::A3), 10);
        let req = d.request.as_ref().unwrap();
        assert_eq!(d.state, DraftState::AwaitingConsent);
        assert_eq!(
            (req.level, req.selection),
            (
                Level::A3,
                Selection::AboveAvailable(Channel::TelegramMiniAppPin)
            )
        );
        assert_eq!(
            d.clone().decide(&attempt(&d, Channel::TelegramMiniApp), 20),
            Err(DecisionError::ChannelTooWeak)
        );
        let approved = d
            .clone()
            .decide(&attempt(&d, Channel::TelegramMiniAppPin), 20)
            .unwrap()
            .unwrap();
        assert_eq!(
            (approved.level, approved.required),
            (Level::A2Plus, Level::A3)
        );
    }

    #[test]
    fn a_satisfiable_level_is_approved_at_that_level() {
        let d = awaiting(1, 1, "hi", 0, 1000, Required::Level(Level::A2Plus), 10);
        assert_eq!(
            d.request.as_ref().unwrap().selection,
            Selection::Satisfies(Channel::TelegramMiniAppPin)
        );
        assert_eq!(
            d.clone().decide(&attempt(&d, Channel::TelegramMiniApp), 20),
            Err(DecisionError::ChannelTooWeak)
        );
        let approved = d
            .clone()
            .decide(&attempt(&d, Channel::TelegramMiniAppPin), 20)
            .unwrap()
            .unwrap();
        assert_eq!(
            (approved.level, approved.required),
            (Level::A2Plus, Level::A2Plus)
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
    fn the_prompt_ttl_setting_is_bounded() {
        let (lo, hi) = (*PROMPT_TTL_RANGE.start(), *PROMPT_TTL_RANGE.end());
        for ttl in [lo, PROMPT_TTL_DEFAULT, hi] {
            assert_eq!(prompt_ttl(ttl), Ok(ttl));
        }
        for bad in [0, lo - 1, hi + 1] {
            assert_eq!(prompt_ttl(bad), Err(PromptTtlOutOfRange(bad)));
        }
    }

    #[test]
    fn the_pending_limit_counts_only_the_tenants_drafts_awaiting_consent() {
        use DraftState::{AwaitingConsent, Released};
        let refused = Err(DraftError::RateLimited(DraftLimit::PendingPerTenant));
        let cases: [(Vec<Draft>, Result<(), DraftError>); 4] = [
            (drafts(1, 49, "carol", 0, AwaitingConsent), Ok(())),
            (drafts(1, 50, "carol", 0, AwaitingConsent), refused),
            (drafts(2, 50, "carol", 0, AwaitingConsent), Ok(())),
            (drafts(1, 50, "carol", 0, Released), Ok(())),
        ];
        for (i, (ds, want)) in cases.into_iter().enumerate() {
            assert_eq!(admit(&ds, &tenant(1), &peer("bob"), 10), want, "case {i}");
        }
    }

    #[test]
    fn the_peer_limit_counts_drafts_to_that_peer_in_a_sliding_hour() {
        use DraftState::Released;
        let refused = Err(DraftError::RateLimited(DraftLimit::PerPeerHour));
        let mut thirty = drafts(1, 1, "bob", 0, Released);
        thirty.extend(drafts(1, 29, "bob", 100, Released));
        let cases: [(Vec<Draft>, UnixSecs, Result<(), DraftError>); 7] = [
            (drafts(1, 29, "bob", 100, Released), 200, Ok(())),
            (thirty.clone(), 200, refused),
            (thirty.clone(), 3599, refused),
            (thirty.clone(), 3600, Ok(())),
            (thirty, 3700, Ok(())),
            (drafts(1, 30, "carol", 100, Released), 200, Ok(())),
            (drafts(2, 30, "bob", 100, Released), 200, Ok(())),
        ];
        for (i, (ds, now, want)) in cases.into_iter().enumerate() {
            assert_eq!(admit(&ds, &tenant(1), &peer("bob"), now), want, "case {i}");
        }
    }

    #[test]
    fn no_prompt_outlives_the_draft() {
        let mut d = awaiting(1, 1, "hi", 0, 1000, Required::Level(Level::A1), 10);
        d.expires = 50;
        d.revise(1, rev("hi!"), 20).unwrap();
        d.evaluated(
            Required::Level(Level::A1),
            &mvp_channels(),
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
        let snap = awaiting(1, 1, "hi", 0, 1000, Required::Level(Level::A1), 10);
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
