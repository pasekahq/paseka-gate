//! Mandate verification: closed (one message) and open (a constrained class of messages).

use std::collections::{BTreeMap, VecDeque};

use paseka_proto::evidence::{self, Channel, Proof};
use paseka_proto::jws::TYP_MANDATE;
use paseka_proto::mandate::{AttachmentRef, ClosedMandate, Mandate, OpenMandate};
use paseka_proto::{Level, Nonce, PeerId, TenantId, UnixSecs};

use crate::hash::content_sha256;
use crate::nonce::{Binding, NonceBook, NonceError};
use crate::risk;
use crate::token::{self, ApproverRing, TokenError};

/// Longest accepted lifetime of a closed mandate, measured from `now`. Approval channels issue
/// about 60 s; the slack absorbs clock skew between channel and gate.
pub const MAX_CLOSED_TTL_SECS: u64 = 120;
/// Longest accepted lifetime of an open mandate.
pub const MAX_OPEN_TTL_SECS: u64 = 30 * 24 * 3600;

/// The message the gate is about to release.
#[derive(Debug, Clone, Copy)]
pub struct Outgoing<'a> {
    /// Tenant releasing it.
    pub tenant: &'a TenantId,
    /// Recipient.
    pub to: &'a PeerId,
    /// Exact text.
    pub text: &'a str,
    /// Attachments.
    pub attachments: &'a [AttachmentRef],
}

/// Why a mandate does not authorise a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MandateError {
    /// Token-level failure: shape, algorithm, type, key or signature.
    Token(TokenError),
    /// Payload is not a valid mandate.
    Payload,
    /// Closed mandate where an open one was expected, or the reverse.
    WrongKind,
    /// Signed by a key of another tenant, or names another tenant.
    WrongTenant,
    /// Names another recipient.
    WrongRecipient,
    /// Content digest differs from the outgoing text.
    HashMismatch,
    /// Attachment list differs.
    AttachmentsMismatch,
    /// Past `exp`.
    Expired,
    /// Before `nbf`.
    NotYetValid,
    /// Lifetime beyond the allowed maximum.
    TtlTooLong,
    /// Level below the required one.
    LevelTooLow,
    /// Channel unknown or unable to attest the claimed level.
    ChannelCannotAttest,
    /// Approver key not allowed to attest the claimed level.
    ApproverCannotAttest,
    /// Nonce failure.
    Nonce(NonceError),
}

impl From<TokenError> for MandateError {
    fn from(e: TokenError) -> Self {
        Self::Token(e)
    }
}

fn open_token(
    ring: &ApproverRing,
    token: &str,
) -> Result<(TenantId, Level, Mandate), MandateError> {
    let ((tenant, max), payload) = token::verify(token, TYP_MANDATE, |kid| {
        ring.get(kid)
            .map(|a| (&a.key, (a.tenant.clone(), a.max_level)))
    })?;
    let m = serde_json::from_slice(&payload).map_err(|_| MandateError::Payload)?;
    Ok((tenant, max, m))
}

fn check_attestation(proof: &Proof, level: Level, approver_max: Level) -> Result<(), MandateError> {
    match evidence::max_level(proof.channel) {
        Some(ch) if level <= ch => {}
        _ => return Err(MandateError::ChannelCannotAttest),
    }
    if level > approver_max {
        return Err(MandateError::ApproverCannotAttest);
    }
    Ok(())
}

/// Verifies a closed mandate for `out` at `required` level and consumes its nonce.
///
/// The nonce is consumed only after every other check passed, so a rejected token never burns
/// a valid nonce.
///
/// # Errors
/// [`MandateError`] naming the first failed check.
pub fn verify_closed(
    ring: &ApproverRing,
    nonces: &mut NonceBook,
    token: &str,
    out: Outgoing<'_>,
    required: Level,
    now: UnixSecs,
) -> Result<ClosedMandate, MandateError> {
    let (key_tenant, approver_max, m) = open_token(ring, token)?;
    let Mandate::Closed(m) = m else {
        return Err(MandateError::WrongKind);
    };
    if &key_tenant != out.tenant || &m.tenant != out.tenant {
        return Err(MandateError::WrongTenant);
    }
    if &m.to != out.to {
        return Err(MandateError::WrongRecipient);
    }
    if m.content_sha256 != content_sha256(out.text) {
        return Err(MandateError::HashMismatch);
    }
    if m.attachments != out.attachments {
        return Err(MandateError::AttachmentsMismatch);
    }
    if now >= m.exp {
        return Err(MandateError::Expired);
    }
    if m.exp > now.saturating_add(MAX_CLOSED_TTL_SECS) {
        return Err(MandateError::TtlTooLong);
    }
    if m.level < required {
        return Err(MandateError::LevelTooLow);
    }
    check_attestation(&m.proof, m.level, approver_max)?;
    let binding = Binding {
        to: m.to.clone(),
        content_sha256: m.content_sha256,
    };
    nonces
        .consume(out.tenant, &m.nonce, &binding, now)
        .map_err(MandateError::Nonce)?;
    Ok(m)
}

/// Verifies an open mandate's signature, scope and window; does not check a message.
///
/// An open mandate MUST be signed through a human channel (level at least A1).
///
/// # Errors
/// [`MandateError`] naming the first failed check.
pub fn verify_open(
    ring: &ApproverRing,
    token: &str,
    tenant: &TenantId,
    to: &PeerId,
    now: UnixSecs,
) -> Result<OpenMandate, MandateError> {
    let (key_tenant, approver_max, m) = open_token(ring, token)?;
    let Mandate::Open(m) = m else {
        return Err(MandateError::WrongKind);
    };
    if &key_tenant != tenant || &m.tenant != tenant {
        return Err(MandateError::WrongTenant);
    }
    if &m.to != to {
        return Err(MandateError::WrongRecipient);
    }
    if now < m.nbf {
        return Err(MandateError::NotYetValid);
    }
    if now >= m.exp {
        return Err(MandateError::Expired);
    }
    if m.exp.saturating_sub(m.nbf) > MAX_OPEN_TTL_SECS {
        return Err(MandateError::TtlTooLong);
    }
    if m.signed_at_level < Level::A1 || m.proof.channel == Channel::Policy {
        return Err(MandateError::LevelTooLow);
    }
    check_attestation(&m.proof, m.signed_at_level, approver_max)?;
    Ok(m)
}

/// Why a message falls outside a verified open mandate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenDenied {
    /// Longer than `max_len`.
    TooLong,
    /// Matches none of the templates.
    NoTemplate,
    /// Has attachments the mandate does not allow.
    Attachments,
    /// Used private sources the mandate does not allow.
    PrivateSources,
    /// Rate limit reached.
    Rate,
    /// Outside the validity window.
    Window,
}

/// Send times per open mandate, for its rate limit.
#[derive(Debug, Clone, Default)]
pub struct RateLedger {
    sent: BTreeMap<(TenantId, Nonce), VecDeque<UnixSecs>>,
}

/// Checks `out` against open mandate `m` and, if it fits, records the send in `ledger`.
///
/// # Errors
/// [`OpenDenied`] naming the first violated constraint.
pub fn admit_open(
    m: &OpenMandate,
    out: Outgoing<'_>,
    private_sources_used: bool,
    ledger: &mut RateLedger,
    now: UnixSecs,
) -> Result<(), OpenDenied> {
    let c = &m.constraints;
    if now < m.nbf || now >= m.exp {
        return Err(OpenDenied::Window);
    }
    if out.text.len() > c.max_len as usize {
        return Err(OpenDenied::TooLong);
    }
    if !c.templates.is_empty()
        && !c
            .templates
            .iter()
            .any(|t| Template::parse(t).is_some_and(|t| t.matches(out.text)))
    {
        return Err(OpenDenied::NoTemplate);
    }
    if !out.attachments.is_empty() && !c.attachments {
        return Err(OpenDenied::Attachments);
    }
    if private_sources_used && !c.private_sources {
        return Err(OpenDenied::PrivateSources);
    }
    let sent = ledger
        .sent
        .entry((m.tenant.clone(), m.nonce.clone()))
        .or_default();
    while sent
        .front()
        .is_some_and(|&t| t.saturating_add(c.rate.per_secs) <= now)
    {
        sent.pop_front();
    }
    if sent.len() >= c.rate.max_messages as usize {
        return Err(OpenDenied::Rate);
    }
    sent.push_back(now);
    Ok(())
}

/// Lifecycle of the open mandate offered to the owner for one (tenant, peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotState {
    Presented,
    Active,
    Refused,
}

/// Why a new open mandate cannot be presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotError {
    /// The previous one is still presented or active and unexpired; it must be refused first.
    PreviousNotRefused,
    /// No such presented mandate.
    NotPresented,
}

/// Enforces that a new open mandate is presented only after the previous one was refused or
/// expired.
#[derive(Debug, Clone, Default)]
pub struct OpenSlots {
    slots: BTreeMap<(TenantId, PeerId), (Nonce, UnixSecs, SlotState)>,
}

impl OpenSlots {
    /// Presents a new open mandate identified by `nonce`, valid until `exp`.
    ///
    /// # Errors
    /// [`SlotError::PreviousNotRefused`] while the previous one is pending or active.
    pub fn present(
        &mut self,
        tenant: &TenantId,
        to: &PeerId,
        nonce: Nonce,
        exp: UnixSecs,
        now: UnixSecs,
    ) -> Result<(), SlotError> {
        let key = (tenant.clone(), to.clone());
        if let Some((_, old_exp, state)) = self.slots.get(&key) {
            if *state != SlotState::Refused && now < *old_exp {
                return Err(SlotError::PreviousNotRefused);
            }
        }
        self.slots.insert(key, (nonce, exp, SlotState::Presented));
        Ok(())
    }

    fn set(
        &mut self,
        tenant: &TenantId,
        to: &PeerId,
        nonce: &Nonce,
        s: SlotState,
    ) -> Result<(), SlotError> {
        match self.slots.get_mut(&(tenant.clone(), to.clone())) {
            Some((n, _, state)) if n == nonce => {
                *state = s;
                Ok(())
            }
            _ => Err(SlotError::NotPresented),
        }
    }

    /// The owner signed the presented mandate.
    ///
    /// # Errors
    /// [`SlotError::NotPresented`] if `nonce` is not the current one.
    pub fn activate(
        &mut self,
        tenant: &TenantId,
        to: &PeerId,
        nonce: &Nonce,
    ) -> Result<(), SlotError> {
        self.set(tenant, to, nonce, SlotState::Active)
    }

    /// The owner refused or revoked the current mandate.
    ///
    /// # Errors
    /// [`SlotError::NotPresented`] if `nonce` is not the current one.
    pub fn refuse(
        &mut self,
        tenant: &TenantId,
        to: &PeerId,
        nonce: &Nonce,
    ) -> Result<(), SlotError> {
        self.set(tenant, to, nonce, SlotState::Refused)
    }

    /// Whether `nonce` is the current, active, unexpired mandate.
    pub fn is_active(&self, tenant: &TenantId, to: &PeerId, nonce: &Nonce, now: UnixSecs) -> bool {
        self.slots
            .get(&(tenant.clone(), to.clone()))
            .is_some_and(|(n, exp, s)| n == nonce && *s == SlotState::Active && now < *exp)
    }
}

/// Longest value of one template slot.
pub const MAX_SLOT_BYTES: usize = 64;

/// A parsed template: literal text with `{name}` slots. Slots must be separated by literal text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    parts: Vec<Part>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Lit(String),
    Slot,
}

impl Template {
    /// Parses `src`; `None` for unbalanced braces, empty slot names or adjacent slots.
    pub fn parse(src: &str) -> Option<Self> {
        let mut parts = Vec::new();
        let mut rest = src;
        while let Some(open) = rest.find('{') {
            let close = open + rest[open..].find('}')?;
            let name = &rest[open + 1..close];
            if name.is_empty() || name.contains('{') {
                return None;
            }
            if open > 0 {
                parts.push(Part::Lit(rest[..open].to_owned()));
            } else if matches!(parts.last(), Some(Part::Slot)) {
                return None;
            }
            parts.push(Part::Slot);
            rest = &rest[close + 1..];
        }
        if rest.contains('}') {
            return None;
        }
        if !rest.is_empty() {
            parts.push(Part::Lit(rest.to_owned()));
        }
        Some(Self { parts })
    }

    /// Whether `text` is this template with every slot filled by a short, flag-free value.
    pub fn matches(&self, text: &str) -> bool {
        let mut rest = text;
        let mut pending_slot = false;
        for part in &self.parts {
            match part {
                Part::Slot => pending_slot = true,
                Part::Lit(lit) if pending_slot => {
                    let Some(at) = rest.find(lit.as_str()) else {
                        return false;
                    };
                    if !slot_value_ok(&rest[..at]) {
                        return false;
                    }
                    rest = &rest[at + lit.len()..];
                    pending_slot = false;
                }
                Part::Lit(lit) => match rest.strip_prefix(lit.as_str()) {
                    Some(r) => rest = r,
                    None => return false,
                },
            }
        }
        if pending_slot {
            slot_value_ok(rest)
        } else {
            rest.is_empty()
        }
    }
}

fn slot_value_ok(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_SLOT_BYTES
        && !v.contains('\n')
        && risk::structural(v).is_empty()
}

#[cfg(test)]
mod tests;
