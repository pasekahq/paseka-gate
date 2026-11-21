//! The source registry (PROTOCOL §6.4): for every source and peer the owner sets Allow, Ask or
//! Never. Evaluation reads one tenant's decisions towards one peer as [`Decisions`]. One-time
//! codes are always Never; Never is set or lifted only on the settings page.

use std::collections::BTreeMap;

use paseka_proto::evidence::Channel;
use paseka_proto::{Address, TenantId};

use crate::channel::SETTING_LEVEL;
use crate::tenant::TenantMap;

/// The owner's decision for one source towards one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Access {
    /// A hit adds no floor and is no flag for the open mandate stage S12.
    Allow,
    /// A hit raises the floor to the stage's floor and is a flag.
    Ask,
    /// A hit blocks the draft.
    Never,
}

/// A source caught by a built-in detector; one per tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BuiltIn {
    /// API keys, tokens and private keys (S4).
    Secrets,
    /// Card numbers and IBANs (S5).
    PersonalIds,
    /// One-time codes, 2FA and OTP. Always [`Access::Never`].
    OneTimeCodes,
}

/// Kind of a source the owner registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceKind {
    /// Files and folders, caught by fingerprints (S8).
    Files,
    /// The agent's memory, skills, CLAUDE.md and system prompt, caught by fingerprints (S8).
    AgentContext,
    /// An MCP source such as mail, calendar or contacts, caught by reads in the source log (S9).
    Mcp,
    /// The messages one peer sent, caught by fingerprints of their bodies (S8).
    PeerInbound,
    /// Memory entries tagged as about third parties, caught by fingerprints (S8).
    ThirdParties,
}

/// The gate's id of one registered source in a tenant's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId(pub u32);

/// A source of the registry: what a detection stage reports when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// The source of a built-in detector.
    BuiltIn(BuiltIn),
    /// A registered source.
    Registered(SourceId),
}

/// One tenant's decisions towards one peer. A source without a decision is [`Access::Ask`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decisions(BTreeMap<Source, Access>);

impl Decisions {
    /// No decisions: every source is Ask, one-time codes Never.
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// The decision for `source`.
    pub fn access(&self, source: Source) -> Access {
        if source == Source::BuiltIn(BuiltIn::OneTimeCodes) {
            return Access::Never;
        }
        self.0.get(&source).copied().unwrap_or(Access::Ask)
    }
}

/// Where an owner decision on the registry is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    /// The settings page of the Mini App.
    Settings,
    /// An approval prompt, for a draft or an open mandate.
    Prompt,
}

/// An owner decision to set the access of one source towards one peer.
#[derive(Debug, Clone, Copy)]
pub struct Change<'a> {
    /// Tenant resolved from the channel, never from a payload.
    pub tenant: &'a TenantId,
    /// The source.
    pub source: Source,
    /// The peer.
    pub peer: &'a Address,
    /// The new access.
    pub access: Access,
    /// Where the owner decided.
    pub surface: Surface,
    /// The channel the decision came through.
    pub channel: Channel,
}

/// A refused registry change or registration. The registry is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeError {
    /// One-time codes are always Never.
    Fixed,
    /// The source id is not registered in the tenant.
    UnknownSource,
    /// The source id is already registered in the tenant.
    AlreadyRegistered,
    /// The channel does not satisfy the settings floor A2.
    ChannelTooWeak,
    /// Never is set or lifted only on the settings page.
    NeverOnlyInSettings,
}

/// The per-tenant source registry: registered sources and the owner's decisions per peer.
#[derive(Debug, Clone, Default)]
pub struct SourceRegistry {
    registered: TenantMap<SourceId, SourceKind>,
    decisions: TenantMap<Address, Decisions>,
}

impl SourceRegistry {
    /// Registers source `id` of `kind` in `tenant`. Its decisions start at Ask for every peer.
    ///
    /// # Errors
    /// [`ChangeError::AlreadyRegistered`] when `id` exists in `tenant`.
    pub fn register(
        &mut self,
        tenant: &TenantId,
        id: SourceId,
        kind: SourceKind,
    ) -> Result<(), ChangeError> {
        if self.registered.get(tenant, &id).is_some() {
            return Err(ChangeError::AlreadyRegistered);
        }
        self.registered.insert(tenant, id, kind);
        Ok(())
    }

    /// The kind of registered source `id` in `tenant`.
    pub fn kind(&self, tenant: &TenantId, id: SourceId) -> Option<SourceKind> {
        self.registered.get(tenant, &id).copied()
    }

    /// `tenant`'s decisions towards `peer`, the input of evaluation.
    pub fn towards(&self, tenant: &TenantId, peer: &Address) -> Decisions {
        self.decisions
            .get(tenant, peer)
            .cloned()
            .unwrap_or_default()
    }

    /// Applies an owner decision.
    ///
    /// # Errors
    /// [`ChangeError`] naming the first failed check.
    pub fn change(&mut self, c: &Change<'_>) -> Result<(), ChangeError> {
        if c.source == Source::BuiltIn(BuiltIn::OneTimeCodes) {
            return Err(ChangeError::Fixed);
        }
        if let Source::Registered(id) = c.source {
            if self.registered.get(c.tenant, &id).is_none() {
                return Err(ChangeError::UnknownSource);
            }
        }
        if !c.channel.satisfies(SETTING_LEVEL) {
            return Err(ChangeError::ChannelTooWeak);
        }
        let current = self.towards(c.tenant, c.peer).access(c.source);
        let touches_never = current == Access::Never || c.access == Access::Never;
        if touches_never && c.surface != Surface::Settings {
            return Err(ChangeError::NeverOnlyInSettings);
        }
        self.decisions
            .entry(c.tenant, c.peer.clone())
            .0
            .insert(c.source, c.access);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
