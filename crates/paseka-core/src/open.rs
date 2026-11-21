//! Open mandates: shape, matching, counters, the one-pending rule and the agent's view of
//! conversation trust (PROTOCOL §4.4, §8.3, §9.1).
//! Open mandates never leave the issuing gate.

use std::collections::BTreeSet;

use paseka_proto::draft::DraftKind;
use paseka_proto::evidence::Channel;
use paseka_proto::mandate::{AttachmentRule, OpenMandate, PrivateSources};
use paseka_proto::tools::ThreadTrust;
use paseka_proto::{
    Address, Level, MandateId, OpenTrust, ShelfId, TemplateId, TenantId, ThreadId, UnixSecs,
};

use crate::tenant::TenantMap;

const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;

/// Default duration of conversation trust, with no message limit (PROTOCOL §4.4, §14).
pub const CONVERSATION_TTL_DEFAULT: u64 = 30 * 60;

/// Maximum lifetime per trust (PROTOCOL §8.3); for conversation trust it bounds the owner's
/// duration setting (§14).
pub fn max_lifetime(trust: OpenTrust) -> u64 {
    match trust {
        OpenTrust::Conversation => DAY,
        OpenTrust::T1 => 30 * DAY,
        OpenTrust::T2 => 90 * DAY,
        OpenTrust::T3 => 7 * DAY,
    }
}

/// An open mandate whose shape breaks a rule of `contracts/mandate/open` or PROTOCOL §8.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadShape(pub &'static str);

/// Checks the shape rules a deserialiser does not: signing level and channel, per-trust
/// constraints, a non-empty rate except for conversation trust, and the maximum lifetime.
///
/// # Errors
/// [`BadShape`] naming the broken rule.
pub fn check_shape(m: &OpenMandate) -> Result<(), BadShape> {
    let c = &m.constraints;
    if m.signed_at_level < Level::A2 {
        return Err(BadShape("signed below A2"));
    }
    if m.proof.channel == Channel::OpenMandate || !m.proof.channel.satisfies(m.signed_at_level) {
        return Err(BadShape("proof channel cannot attest signed_at_level"));
    }
    let r = &c.rate;
    let empty_rate = r.max_messages.is_none() && r.per_hour.is_none() && r.per_day.is_none();
    if empty_rate && m.trust != OpenTrust::Conversation {
        return Err(BadShape("empty rate"));
    }
    let ok = match m.trust {
        OpenTrust::T1 => !c.templates.is_empty() && c.max_len.is_some(),
        OpenTrust::T2 => !c.shelves.is_empty() && c.attachments == Some(AttachmentRule::Shelf),
        OpenTrust::T3 => !c.topics.is_empty() && c.max_len.is_some() && r.per_day.is_some(),
        OpenTrust::Conversation => c.thread.is_some(),
    };
    if !ok {
        return Err(BadShape("constraints required by the trust are missing"));
    }
    if m.nbf > m.exp || m.exp - m.nbf > max_lifetime(m.trust) {
        return Err(BadShape("lifetime"));
    }
    Ok(())
}

/// The facts about a revision that open-mandate matching looks at.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    /// Recipient address.
    pub to: &'a Address,
    /// What was proposed.
    pub kind: DraftKind,
    /// Template used, for [`DraftKind::Template`].
    pub template: Option<&'a TemplateId>,
    /// Shelf of the shared document, for [`DraftKind::Share`].
    pub shelf: Option<&'a ShelfId>,
    /// Thread.
    pub thread: &'a ThreadId,
    /// Body length in bytes.
    pub body_len: usize,
    /// Whether the revision has attachments not read by the gate from a shelf.
    pub foreign_attachments: bool,
    /// Whether the turn read private sources.
    pub private_sources: bool,
}

/// Why an open mandate does not cover a revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenDenied {
    /// Not active: before `nbf`, after `exp`, revoked, or tripwire mode.
    Inactive,
    /// Another recipient.
    Recipient,
    /// The revision's kind is not allowed by the trust.
    Kind,
    /// A constraint fails.
    Constraint,
    /// Counters exhausted.
    Rate,
}

/// Open mandate state of one gate: revocations, presentation slots and release counters.
#[derive(Debug, Clone, Default)]
pub struct OpenBook {
    revoked: TenantMap<MandateId, ()>,
    slots: TenantMap<(Address, &'static str), Slot>,
    sent: TenantMap<MandateId, Vec<UnixSecs>>,
}

#[derive(Debug, Clone, Default)]
struct Slot {
    active: Option<(MandateId, UnixSecs)>,
    pending: Option<(MandateId, UnixSecs)>,
}

/// A refused presentation (AP2 rule, PROTOCOL §8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotError {
    /// A pending open mandate for this peer and trust is still live.
    PreviousPending,
    /// No such pending mandate.
    NotPending,
}

fn trust_key(t: OpenTrust) -> &'static str {
    match t {
        OpenTrust::T1 => "T1",
        OpenTrust::T2 => "T2",
        OpenTrust::T3 => "T3",
        OpenTrust::Conversation => "conversation",
    }
}

fn live(x: Option<&(MandateId, UnixSecs)>, now: UnixSecs) -> bool {
    x.is_some_and(|(_, exp)| now < *exp)
}

impl OpenBook {
    /// Presents `m` to the owner. Refused while a previous one for the same peer and trust is
    /// pending.
    ///
    /// # Errors
    /// [`SlotError::PreviousPending`].
    pub fn present(&mut self, m: &OpenMandate, now: UnixSecs) -> Result<(), SlotError> {
        let slot = self
            .slots
            .entry(&m.tenant, (m.to.clone(), trust_key(m.trust)));
        if live(slot.pending.as_ref(), now) {
            return Err(SlotError::PreviousPending);
        }
        slot.pending = Some((m.jti.clone(), m.exp));
        Ok(())
    }

    /// The owner signed the pending `m`; it replaces the active one.
    ///
    /// # Errors
    /// [`SlotError::NotPending`] unless `m` is the pending mandate.
    pub fn activate(&mut self, m: &OpenMandate) -> Result<(), SlotError> {
        let slot = self
            .slots
            .get_mut(&m.tenant, &(m.to.clone(), trust_key(m.trust)))
            .ok_or(SlotError::NotPending)?;
        if slot.pending.as_ref().map(|p| &p.0) != Some(&m.jti) {
            return Err(SlotError::NotPending);
        }
        slot.active = slot.pending.take();
        Ok(())
    }

    /// The owner refused the pending `m`.
    pub fn refuse(&mut self, m: &OpenMandate) {
        if let Some(slot) = self
            .slots
            .get_mut(&m.tenant, &(m.to.clone(), trust_key(m.trust)))
        {
            if slot.pending.as_ref().map(|p| &p.0) == Some(&m.jti) {
                slot.pending = None;
            }
        }
    }

    /// Revokes `jti`; effective for every evaluation that starts afterwards.
    pub fn revoke(&mut self, tenant: &TenantId, jti: &MandateId) {
        self.revoked.insert(tenant, jti.clone(), ());
    }

    fn is_active(&self, m: &OpenMandate, now: UnixSecs) -> bool {
        let slot = self
            .slots
            .get(&m.tenant, &(m.to.clone(), trust_key(m.trust)));
        slot.and_then(|s| s.active.as_ref())
            .is_some_and(|(j, _)| j == &m.jti)
            && self.revoked.get(&m.tenant, &m.jti).is_none()
            && m.nbf <= now
            && now < m.exp
    }

    fn counts_ok(&self, m: &OpenMandate, now: UnixSecs) -> bool {
        let sent = self
            .sent
            .get(&m.tenant, &m.jti)
            .map_or(&[][..], Vec::as_slice);
        let within = |w: u64| sent.iter().filter(|&&t| t.saturating_add(w) > now).count();
        let r = &m.constraints.rate;
        let under = |limit: Option<u32>, n: usize| limit.is_none_or(|l| n < l as usize);
        under(r.max_messages, sent.len())
            && under(r.per_hour, within(HOUR))
            && under(r.per_day, within(DAY))
    }

    /// Whether `m` covers `c` now (PROTOCOL §9.1). Does not consume a counter.
    ///
    /// # Errors
    /// [`OpenDenied`] for the first failed condition.
    pub fn matches(
        &self,
        m: &OpenMandate,
        c: &Candidate<'_>,
        tripwire: bool,
        now: UnixSecs,
    ) -> Result<(), OpenDenied> {
        if tripwire || !self.is_active(m, now) {
            return Err(OpenDenied::Inactive);
        }
        if &m.to != c.to {
            return Err(OpenDenied::Recipient);
        }
        let k = &m.constraints;
        let kind_ok = match (m.trust, c.kind) {
            (OpenTrust::T1, DraftKind::Template) => {
                c.template.is_some_and(|t| k.templates.contains(t))
            }
            (OpenTrust::T2, DraftKind::Share) => c.shelf.is_some_and(|s| k.shelves.contains(s)),
            (OpenTrust::Conversation, DraftKind::FreeText) => k.thread.as_ref() == Some(c.thread),
            _ => false,
        };
        if !kind_ok {
            return Err(OpenDenied::Kind);
        }
        let len_ok = k.max_len.is_none_or(|l| c.body_len <= l as usize);
        let private_ok = !c.private_sources || k.private_sources == Some(PrivateSources::Allow);
        if !len_ok || !private_ok || c.foreign_attachments {
            return Err(OpenDenied::Constraint);
        }
        if !self.counts_ok(m, now) {
            return Err(OpenDenied::Rate);
        }
        Ok(())
    }

    /// Consumes one message under `m` in the release transaction; returns the 1-based counter.
    pub fn consume(&mut self, m: &OpenMandate, now: UnixSecs) -> u32 {
        let sent = self.sent.entry(&m.tenant, m.jti.clone());
        sent.push(now);
        u32::try_from(sent.len()).unwrap_or(u32::MAX)
    }
}

/// Shelves named by the active T2 mandates in `ms` for recipient `to`.
pub fn open_shelves<'a>(
    book: &OpenBook,
    ms: &'a [OpenMandate],
    to: &Address,
    now: UnixSecs,
) -> BTreeSet<&'a ShelfId> {
    ms.iter()
        .filter(|m| m.trust == OpenTrust::T2 && &m.to == to && book.is_active(m, now))
        .flat_map(|m| m.constraints.shelves.iter())
        .collect()
}

/// Conversation trust of `thread` with `peer` as the agent sees it (PROTOCOL §4.4). Active only
/// for a conversation mandate of `tenant` in `ms` on that exact thread and peer that is active,
/// outside tripwire mode and has a message left; `seconds_left` counts from `now` to its `exp`.
pub fn thread_trust(
    book: &OpenBook,
    ms: &[OpenMandate],
    tenant: &TenantId,
    peer: &Address,
    thread: &ThreadId,
    tripwire: bool,
    now: UnixSecs,
) -> ThreadTrust {
    let ends_at = ms
        .iter()
        .filter(|m| {
            !tripwire
                && &m.tenant == tenant
                && m.trust == OpenTrust::Conversation
                && &m.to == peer
                && m.constraints.thread.as_ref() == Some(thread)
                && book.is_active(m, now)
                && book.counts_ok(m, now)
        })
        .map(|m| m.exp)
        .max();
    ThreadTrust {
        active: ends_at.is_some(),
        ends_at,
        seconds_left: ends_at.map(|exp| exp - now),
        new_thread_needs_owner: true,
    }
}

#[cfg(test)]
mod tests;
