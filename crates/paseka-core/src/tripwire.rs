//! Tripwire mode (PROTOCOL §4.3): what a canary hit does beyond blocking its draft. Under the
//! default full alarm the tenant stops every open mandate and raises every draft to
//! [`TRIPWIRE_LEVEL`] until the owner clears it through a channel at that level; nothing weaker,
//! no open mandate and no agent call clears it.

use paseka_proto::evidence::Channel;
use paseka_proto::{DraftId, Level, Nonce, PeerHandle, RequestId, TenantId, UnixSecs};

use crate::draft::{Draft, RequestSeed};
use crate::risk::{Assessment, CanaryId};
use crate::tenant::TenantMap;

/// Floor of every draft while tripwire mode is in effect (S11), and the level a clear needs:
/// in the MVP only `telegram-miniapp-pin` satisfies it.
pub const TRIPWIRE_LEVEL: Level = Level::A2Plus;
/// Floor of a security setting change (PROTOCOL §9.4).
const SETTING_LEVEL: Level = Level::A2;

/// What a canary hit does beyond blocking its draft: a security setting (PROTOCOL §9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TripwireMode {
    /// The tenant enters tripwire mode: open mandates stop and every draft needs
    /// [`TRIPWIRE_LEVEL`] until the owner clears it.
    #[default]
    FullAlarm,
    /// Only the draft with the canary is blocked; other drafts and open mandates are unaffected.
    DraftBlockOnly,
}

/// The span of the gate's MCP journal covering the agent turn that proposed the revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpWindow {
    /// First second of the turn.
    pub from: UnixSecs,
    /// Last second of the turn.
    pub until: UnixSecs,
}

/// One canary hit as recorded and shown to the owner. Holds no canary marker and no body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trigger {
    /// Recipient of the blocked draft.
    pub peer: PeerHandle,
    /// The blocked draft.
    pub draft: DraftId,
    /// Its blocked revision.
    pub revision: u32,
    /// Canaries that matched, by id.
    pub canaries: Vec<CanaryId>,
    /// Where the owner reads what the agent did in that turn.
    pub journal: McpWindow,
    /// Time of the hit.
    pub at: UnixSecs,
}

/// What a hit did to the tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alarm {
    /// The hit put the tenant into tripwire mode.
    Entered,
    /// Tripwire mode was already active; the hit joined its triggers.
    Added,
    /// Mode [`TripwireMode::DraftBlockOnly`]: only the draft is blocked.
    DraftOnly,
}

/// The owner notice of one canary hit; the gate sends it once per hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// Tenant of the blocked draft.
    pub tenant: TenantId,
    /// The hit.
    pub trigger: Trigger,
    /// What it did.
    pub alarm: Alarm,
}

/// A live request to clear tripwire mode, opened when the owner asks to clear it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearRequest {
    /// Request id.
    pub request_id: RequestId,
    /// Gate nonce.
    pub nonce: Nonce,
    /// Issue time.
    pub issued_at: UnixSecs,
    /// End of the prompt TTL.
    pub expires_at: UnixSecs,
}

/// Tripwire mode of one tenant while it is active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Active {
    /// Every hit since entering, the first one first.
    pub triggers: Vec<Trigger>,
    /// The live clear request; a new hit revokes it.
    pub clear: Option<ClearRequest>,
}

/// A clear decision as received from an approval channel.
#[derive(Debug, Clone, Copy)]
pub struct ClearAttempt<'a> {
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
}

/// A refused clear. Tripwire mode stays active and the request stays open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearError {
    /// Tripwire mode is not active for this tenant.
    NotActive,
    /// No live clear request with this id.
    UnknownRequest,
    /// The nonce does not belong to the request.
    NonceMismatch,
    /// The prompt TTL passed.
    Expired,
    /// The channel does not satisfy [`TRIPWIRE_LEVEL`].
    ChannelTooWeak,
    /// The decider is not an approver of the tenant.
    NotApprover,
}

/// A refused change of [`TripwireMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeError {
    /// The channel does not satisfy the settings floor A2.
    ChannelTooWeak,
    /// Tripwire mode is active; only a clear ends it.
    TripwireActive,
}

#[derive(Debug, Clone, Default)]
struct State {
    mode: TripwireMode,
    active: Option<Active>,
}

/// Per-tenant tripwire mode and setting. Active implies [`TripwireMode::FullAlarm`]: a hit enters
/// only under it, and the mode cannot change while active.
#[derive(Debug, Clone, Default)]
pub struct TripwireBook {
    tenants: TenantMap<(), State>,
}

impl TripwireBook {
    /// The tenant's mode setting.
    pub fn mode(&self, tenant: &TenantId) -> TripwireMode {
        self.tenants
            .get(tenant, &())
            .map_or_else(TripwireMode::default, |s| s.mode)
    }

    /// The tenant's active tripwire mode, if any.
    pub fn active(&self, tenant: &TenantId) -> Option<&Active> {
        self.tenants.get(tenant, &())?.active.as_ref()
    }

    /// Whether tripwire mode is in effect: the `tripwire` input of risk evaluation and of
    /// open-mandate matching.
    pub fn in_effect(&self, tenant: &TenantId) -> bool {
        self.active(tenant).is_some()
    }

    /// Changes the tenant's mode through an owner settings decision by `channel`.
    ///
    /// # Errors
    /// [`ModeError::TripwireActive`] while active, whatever the channel;
    /// [`ModeError::ChannelTooWeak`] for a channel below A2.
    pub fn set_mode(
        &mut self,
        tenant: &TenantId,
        mode: TripwireMode,
        channel: Channel,
    ) -> Result<(), ModeError> {
        if self.in_effect(tenant) {
            return Err(ModeError::TripwireActive);
        }
        if !channel.satisfies(SETTING_LEVEL) {
            return Err(ModeError::ChannelTooWeak);
        }
        self.tenants.entry(tenant, ()).mode = mode;
        Ok(())
    }

    /// Records the canary hits of `assessed`, the evaluation of `draft`'s current revision, which
    /// that evaluation blocked. Returns the owner notice, or `None` when no canary matched.
    pub fn canary_hit(
        &mut self,
        draft: &Draft,
        assessed: &Assessment,
        journal: McpWindow,
        now: UnixSecs,
    ) -> Option<Notice> {
        if assessed.canaries.is_empty() {
            return None;
        }
        let trigger = Trigger {
            peer: draft.to.clone(),
            draft: draft.id.clone(),
            revision: draft.revision,
            canaries: assessed.canaries.clone(),
            journal,
            at: now,
        };
        let state = self.tenants.entry(&draft.tenant, ());
        let alarm = match (state.mode, &mut state.active) {
            (TripwireMode::DraftBlockOnly, _) => Alarm::DraftOnly,
            (TripwireMode::FullAlarm, Some(active)) => {
                active.triggers.push(trigger.clone());
                active.clear = None;
                Alarm::Added
            }
            (TripwireMode::FullAlarm, slot @ None) => {
                *slot = Some(Active {
                    triggers: vec![trigger.clone()],
                    clear: None,
                });
                Alarm::Entered
            }
        };
        Some(Notice {
            tenant: draft.tenant.clone(),
            trigger,
            alarm,
        })
    }

    /// Opens a clear request for the owner, replacing any earlier one.
    ///
    /// # Errors
    /// [`ClearError::NotActive`] when tripwire mode is not active.
    pub fn request_clear(
        &mut self,
        tenant: &TenantId,
        seed: RequestSeed,
        now: UnixSecs,
        ttl: u64,
    ) -> Result<ClearRequest, ClearError> {
        let active = self
            .tenants
            .get_mut(tenant, &())
            .and_then(|s| s.active.as_mut())
            .ok_or(ClearError::NotActive)?;
        let req = ClearRequest {
            request_id: seed.request_id,
            nonce: seed.nonce,
            issued_at: now,
            expires_at: now.saturating_add(ttl),
        };
        active.clear = Some(req.clone());
        Ok(req)
    }

    /// Clears tripwire mode on an owner decision for the live clear request. Returns the
    /// triggers it held, for the journal.
    ///
    /// # Errors
    /// [`ClearError`] naming the first failed check; the state is unchanged.
    pub fn clear(
        &mut self,
        a: &ClearAttempt<'_>,
        now: UnixSecs,
    ) -> Result<Vec<Trigger>, ClearError> {
        let state = self
            .tenants
            .get_mut(a.tenant, &())
            .ok_or(ClearError::NotActive)?;
        let Some(active) = state.active.take() else {
            return Err(ClearError::NotActive);
        };
        match check_clear(&active, a, now) {
            Ok(()) => Ok(active.triggers),
            Err(e) => {
                state.active = Some(active);
                Err(e)
            }
        }
    }
}

fn check_clear(active: &Active, a: &ClearAttempt<'_>, now: UnixSecs) -> Result<(), ClearError> {
    let Some(req) = active
        .clear
        .as_ref()
        .filter(|r| &r.request_id == a.request_id)
    else {
        return Err(ClearError::UnknownRequest);
    };
    if &req.nonce != a.nonce {
        return Err(ClearError::NonceMismatch);
    }
    if now >= req.expires_at {
        return Err(ClearError::Expired);
    }
    if !a.channel.satisfies(TRIPWIRE_LEVEL) {
        return Err(ClearError::ChannelTooWeak);
    }
    if !a.approver {
        return Err(ClearError::NotApprover);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
